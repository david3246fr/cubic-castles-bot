#!/usr/bin/env python3
"""
Cubic Castles - Stage 2 WebSocket frame capture driver.

Spawns (or attaches to) Cubic.exe, injects the noPoll hook agent, and records
every inbound/outbound WebSocket frame to:

    captures/<session>.jsonl   structured, full hex, one frame per line
    captures/<session>.log     human-readable hexdump

Action labelling
----------------
Press F9 (works while the game has focus) to advance to the next action in the
checklist. Every frame captured is tagged with the current action label, so
there is no timestamp correlation to do afterwards. F8 steps back if you
overshoot. F7 re-prints the checklist position.

Redaction
---------
Credentials stored in sandbox/settings.txt (System.Username, System.Userpassword,
System.Token) are masked out of frame payloads by default -- both ASCII and
UTF-16LE encodings, and the values are never written to disk. Frame lengths and
structure are preserved so Stage 3 schema work is unaffected.
Use --no-redact to disable.
"""

import argparse
import ctypes
import json
import os
import re
import sys
import threading
import time

try:
    import frida
except ImportError:
    sys.exit("frida not installed:  pip install frida-tools")


GAME_DIR = r"D:\SteamLibrary\steamapps\common\Cubic Castles"
GAME_EXE = "Cubic.exe"
AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nopoll_agent.js")

# Ordered checklist. F9 advances. Chosen to isolate one mechanic at a time and
# to bracket noisy actions with idle periods so the baseline heartbeat traffic
# can be subtracted out during schema mapping.
ACTIONS = [
    "00-startup",              # process start -> title screen
    "01-login",                # enter credentials / Steam auth, press login
    "02-idle-in-world",        # stand perfectly still ~15s (baseline heartbeat)
    # --- movement, one axis at a time, so coordinate fields can be told apart ---
    "03-walk-north",           # hold ONE direction (e.g. up/W) for ~5s, then stop
    "04-idle-a",               # stand still ~5s
    "05-walk-east",            # hold the PERPENDICULAR direction ~5s, then stop
    "06-idle-b",               # stand still ~5s
    "07-walk-back",            # walk back roughly to where you started
    "08-jump-in-place",        # jump straight up repeatedly, no horizontal move
    "09-rotate-camera",        # rotate view only, do not move
    "10-idle-again",           # stand still ~10s
    # --- chat (varying lengths already validated; keep for regression) ---
    "11-chat-short",           # send a short message, e.g. 'hi'
    "12-chat-long",            # send a longer message, e.g. 'the quick brown fox'
    # --- blocks: place at a spot you can identify, one at a time ---
    "13-open-inventory",       # open inventory panel, do nothing else
    "14-select-block",         # select a placeable block in the hotbar
    "15-place-block-1",        # place exactly ONE block, note roughly where
    "16-place-block-2",        # take ONE step, place ONE more (adjacent)
    "17-break-block",          # break exactly ONE block
    "18-pickup-item",          # walk over the dropped item
    "19-open-crafting",        # open crafting panel
    "20-idle-final",           # stand still ~10s
    # --- friends list + teleport-to-friend (the target feature) ---
    "21-open-friends",         # open the friends list panel, do nothing else
    "22-teleport-friend-1",    # teleport to an ONLINE friend (note their name)
    "23-idle-after-tp",        # stand still ~5s after arriving
    "24-teleport-friend-2",    # teleport to a SECOND online friend (note name)
    "25-switch-realm",         # travel to another realm (new backend key)
    "26-logout",               # log out cleanly
]

# Focused checklists for a single feature, so you don't F9 through everything.
# Label names are kept identical to ACTIONS so the analyzers still recognise them.
CHECKLISTS = {
    "full": ACTIONS,
    "teleport": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle in the world ~5s
        "21-open-friends",        # open the friends list
        "22-teleport-friend-1",   # teleport to an online friend (note the name)
        "23-idle-after-tp",       # stand still ~5s after arriving
        "24-teleport-friend-2",   # teleport to a second online friend (note name)
        "26-logout",
    ],
    "friend": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle in the world ~5s
        "27-open-friends",        # open the friends panel
        "28-idle-before-add",     # stand still ~3s (baseline)
        "29-add-friend",          # send a friend request (note the target name)
        "30-idle-after-add",      # stand still ~5s (capture the server's reply)
        "31-add-friend-2",        # OPTIONAL: send a second request (note the name)
        "32-logout",
    ],
    # CHAT EMOJI: isolate the emoji's wire representation from the ordinary chat
    # open/typing toggles. Use one emoji by itself, repeat that exact emoji, then
    # send plain text and a different emoji as controls. Run this checklist with
    # --plaintext so the resulting capture also contains the unencrypted bodies.
    "emoji": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~6s; do not move or type
        "E0-idle-before-emoji",   # stand PERFECTLY still ~6s (clean baseline)
        "E1-open-chat",           # open chat, but type/select nothing yet
        "E2-open-emoji-picker",   # open the emoji picker only; choose nothing
        "E3-insert-emoji-A",      # insert EXACTLY ONE emoji; pause ~3s, do not send
        "E4-send-emoji-A",        # send it by itself; write down which emoji it was
        "E5-idle-after-A",        # close chat and stand still ~5s
        "E6-send-same-emoji-A",   # send that EXACT SAME emoji alone a second time
        "E7-idle-after-repeat",   # close chat and stand still ~5s
        "E8-send-text-control",   # send plain ASCII text: EMOJICTRL
        "E9-idle-after-text",     # close chat and stand still ~5s
        "EA-send-emoji-B",        # send ONE DIFFERENT emoji alone; note which one
        "EB-idle-after-B",        # close chat and stand still ~5s
        "EC-logout",
    ],
    "crosstp": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~5s
        "40-before-tp",           # stand still ~3s right before teleporting
        "41-tp-cross-realm",      # teleport to a friend in a DIFFERENT realm (note name)
        "42-idle-after-arrival",  # STAND STILL ~10s after arriving (key capture window)
        "43-logout",
    ],
    # How does the server decide the world spawn? Hop realms and stand still at
    # each arrival so the placement (rx 0x0005 with our own GUID) is unambiguous.
    # Analyse with:  python cc_spawnlog.py <capture>.jsonl --json spawns.json
    "spawn": [
        "00-startup",
        "01-login",               # log in and then DO NOT MOVE
        "60-spawn-a-idle",        # stand PERFECTLY still ~8s where you landed
        "61-walk-away-a",         # walk well away from where you landed, ~10s
        "62-realm-b",             # travel to a DIFFERENT realm (note its name)
        "63-spawn-b-idle",        # stand still ~8s at the arrival spot
        "64-realm-c",             # travel to a THIRD realm (note its name)
        "65-spawn-c-idle",        # stand still ~8s
        "66-back-to-a",           # go BACK to the first realm — portal, or where you left?
        "67-spawn-a2-idle",       # stand still ~8s
        "68-own-realm",           # travel to YOUR OWN realm
        "69-spawn-own-idle",      # stand still ~8s
        "70-logout",
    ],
    # Name the block type ids. Place ONE known block per step, writing down the
    # block's in-game name as you go; then:
    #   python cc_blocks.py <before>.jsonl --diff <after>.jsonl
    # tells you which type id appeared. Works best in YOUR OWN realm, on empty
    # ground you can find again.
    "blocks": [
        "00-startup",
        "01-login",
        "80-idle-before-build",   # stand still ~6s so the realm's object list lands
        "81-place-block-A",       # place ONE block — WRITE DOWN its name
        "82-idle-a",              # stand still ~5s
        "83-place-block-B",       # place ONE block of a DIFFERENT type — note it
        "84-idle-b",              # stand still ~5s
        "85-place-block-C",       # a THIRD distinct type — note it
        "86-idle-c",              # stand still ~5s
        "87-break-block-A",       # break the FIRST block you placed
        "88-idle-after-break",    # stand still ~5s
        "89-logout",
    ],
    # Vending machines: what is for sale and at what price. The trick is to make
    # the price a value you can search for afterwards — set something
    # distinctive like 4321, never a round 10 or 100. Then:
    #   python cc_findval.py <capture>.jsonl 4321
    # pins the exact message + offset the price lives at, and the item id will
    # be sitting next to it.
    "vending": [
        "00-startup",
        "01-login",
        "90-idle-before",         # stand still ~6s (baseline)
        "91-stock-machine",       # put a KNOWN item in the glass, set price 4321
        "92-idle-after-stock",    # stand still ~5s
        "93-open-machine",        # click the machine and just LOOK — do not buy
        "94-idle-open",           # leave the panel open ~5s, then close it
        "95-open-second",         # open a DIFFERENT machine (note its item+price)
        "96-idle-after",          # stand still ~5s
        "97-walk-away-and-back",  # walk out of range and back — does it resend?
        "98-logout",
    ],
    # BUY: capture a real purchase end to end, INCLUDING a deliberate failure and
    # the wallet balance, to finish the owner-only buy-order feature. The success
    # path (open 0x010f -> dialog 0x00ca -> confirm 0x00ca+01 -> 0x0037 inventory)
    # is already solved in capture-20260814-165759; the two things still missing
    # are the REJECTION message and the CUBIT-BALANCE field.
    #
    # BEFORE you start: read your exact Cubit count off the HUD and write it down.
    # After capturing, find where the balance travels:
    #   python cc_findval.py <capture>.jsonl <your_cubit_count>
    # and, since a successful buy lowers it, also search the NEW count afterwards.
    # For the failure, just grep the decoded capture for the on-screen words
    # (e.g. "enough Cubits"); note them exactly while capturing.
    "buy": [
        "00-startup",
        "01-login",
        "B0-idle-before",         # stand still ~6s (baseline). NOTE your Cubit count now.
        "B1-open-affordable",     # click a machine selling something CHEAP you can afford
        "B2-buy-success",         # CONFIRM the purchase — actually spend
        "B3-idle-after-buy",      # stand still ~5s. NOTE your NEW Cubit count.
        "B4-open-unaffordable",   # open a machine whose price is MORE than you now hold
        "B5-buy-fail",            # CONFIRM it — capture the "not enough Cubits" rejection
        "B6-idle-after-fail",     # stand still ~5s (baseline for the rejection frames)
        "B7-logout",
    ],
    # PRIZE MACHINE / PASSWORD SENTRY: how do you SUBMIT a password guess, and how
    # does the server signal RIGHT vs WRONG? A Prize Dispenser (names.json id 179)
    # guarded by a Password Sentry shows a "WHAT'S THE PASSWORD?" text box on use.
    # Best done on YOUR OWN machine so the correct password is known + reproducible:
    # SET THE PASSWORD to something greppable and non-round like 7391, and stock a
    # KNOWN prize item (write its name down). If you can only test a stranger's
    # machine you'll still get the open + prompt + WRONG path — just skip P5/P6.
    # Analyse afterwards:
    #   grep the decoded capture for 7391   -> the tx that submits the guess + opcode
    #   python cc_findval.py <cap>.jsonl 7391
    #   WRONG path -> the rejection frames ("Wrong Password!"); RIGHT path should end
    #   in the prize landing (watch for rx 0x0037 inventory-changed, like a buy).
    "prize": [
        "00-startup",
        "01-login",
        "P0-idle-before",         # stand PERFECTLY still ~6s near the machine (baseline)
        "P1-open-prize",          # USE the Prize Dispenser — the password box should pop up
        "P2-idle-prompt-open",    # leave the "WHAT'S THE PASSWORD?" box open ~4s, type nothing
        "P3-submit-wrong",        # type a WRONG password (note it) and submit — expect "Wrong Password!"
        "P4-idle-after-wrong",    # stand still ~5s (capture the rejection frames)
        "P5-open-prize-again",    # USE the machine again to reopen the prompt
        "P6-submit-right",        # type the CORRECT password 7391 and submit — expect the prize
        "P7-idle-after-right",    # stand still ~5s (capture the success + inventory change)
        "P8-logout",
    ],
    # PLOT BUMPER: a rented plot guarded by a Bumper. HITTING the bumper pops a
    # dialog. There are TWO dialogs to capture:
    #   (1) LOCKED — while the rental timer is still running: shows the CURRENT
    #       OWNER's name and the TIME LEFT. This is the frame the poll loop reads
    #       to decide "not yet". Note the owner name + the time it displayed.
    #   (2) BUY — once the timer runs out and the plot "goes out": the dialog now
    #       offers to BUY the plot. Clicking YES purchases it.
    # Give the bumper's BLOCK coords (bx,by,bz) — jot them down while capturing.
    # Ideal is both dialogs in one session; if the plot isn't out yet, capture the
    # LOCKED half (U1-U2) now and F9 straight to U6-logout — we grab the BUY half
    # (U3-U5) when a plot is actually available. Analyse afterwards:
    #   grep the decoded capture for the OWNER name string and the time value
    #   -> which rx carried the dialog; which tx (hit) triggered it
    #   python cc_findval.py <cap>.jsonl <seconds-left>   # pins the timer field
    "bumper": [
        "00-startup",
        "01-login",
        "U0-idle-before",         # stand PERFECTLY still ~6s next to the bumper (baseline)
        "U1-hit-bumper-locked",   # HIT the bumper while the timer is RUNNING — note OWNER + TIME shown
        "U2-idle-locked-open",    # leave the locked dialog open ~4s, then close it
        "U3-hit-bumper-open",     # HIT the bumper once the plot has GONE OUT — the BUY dialog appears
        "U4-buy-yes",             # click YES to BUY the plot (actually purchase)
        "U5-idle-after-buy",      # stand still ~6s — capture the confirmation / ownership change
        "U6-logout",
    ],
    # SIGNS: how does the client read a sign's TEXT? Tell two cases apart —
    #   (a) the text ships automatically with the realm's object list on entry
    #       (like a block / vending description: rx 0x000f or rx 0x0014), or
    #   (b) it only arrives when you CLICK the sign (a request + reply, likely
    #       0x0014 block-query or 0x010f use-object).
    # Make the text UNIQUE and easy to grep, e.g. SIGNTEST9987. Then analyse:
    #   python cc_findval.py <capture>.jsonl 9987     # if it pins on the number
    # and grep the capture for the string SIGNTEST9987 to see WHICH tx you sent
    # (the read request) and WHICH rx carried the text back. Do it in YOUR OWN
    # realm so you can place/edit the sign; stand STILL around each step so the
    # sign frames aren't buried in movement.
    "signs": [
        "00-startup",
        "01-login",
        "C0-idle-before",         # stand PERFECTLY still ~6s in your OWN realm
        "C1-place-sign",          # place a SIGN block where you can find it again
        "C2-write-sign",          # write a UNIQUE message on it: SIGNTEST9987
        "C3-idle-after-write",    # stand still ~5s — does the text broadcast now?
        "C4-walk-away",           # walk well out of range of the sign ~6s
        "C5-walk-back-idle",      # walk back near it, stand still ~6s — re-sent?
        "C6-click-read-sign",     # CLICK the sign to READ it — just look, don't edit
        "C7-idle-read-open",      # leave the read panel open ~5s, then close it
        "C8-read-second-sign",    # read a DIFFERENT existing sign (note its text)
        "C9-logout",
    ],
    # DISPLAY INVENTORY: how does a GLASS/DISPLAY CASE report the item inside it,
    # and a MANNEQUIN the wearables dressed on it? Two cases to tell apart, same as
    # signs/vending:
    #   (a) PASSIVE — the shown item is just a stacked world object (rx 0x000f) on
    #       the case/mannequin block, exactly like vending goods. If so we read it
    #       with no interaction: diff the object list before vs after stocking.
    #   (b) ON QUERY/OPEN — contents only come back when you AIM (tx 0x0014 block
    #       query -> rx 0x0014) or OPEN it (tx 0x010f -> a dialog/list reply).
    # Do it in YOUR OWN realm so you can place + stock. Put KNOWN items in (write
    # their in-game names down) and stand STILL around each step. Analyse:
    #   python cc_blocks.py <before>.jsonl --diff <after>.jsonl   # (a): new type_id
    #   grep the capture for the item NAME string, and note which rx carried it
    #   python cc_findval.py <capture>.jsonl <a KNOWN item's type_id>  # pins it
    # The glass-case and mannequin type_ids fall out of the --diff (place-empty vs
    # place-then-stock), and the aim/open frames show whether contents need a request.
    "display": [
        "00-startup",
        "01-login",
        "D0-idle-before",         # stand PERFECTLY still ~6s in your OWN realm (baseline)
        "D1-place-glass-empty",   # place an EMPTY glass/display case — note where
        "D2-idle-empty",          # stand still ~5s (baseline object list WITH empty case)
        "D3-stock-glass",         # put a KNOWN item inside the case — WRITE DOWN its name
        "D4-idle-after-stock",    # stand still ~5s — does the item broadcast now?
        "D5-aim-glass",           # AIM at the case (fires tx 0x0014) — just look
        "D6-open-glass",          # OPEN the case (tx 0x010f) — look, don't change it
        "D7-idle-glass-open",     # leave the panel open ~5s, then close it
        "D8-place-mannequin",     # place a MANNEQUIN — note where
        "D9-dress-mannequin",     # dress it with 1-2 KNOWN wearables — note each name
        "DA-idle-after-dress",    # stand still ~5s
        "DB-aim-mannequin",       # AIM at the mannequin (tx 0x0014)
        "DC-open-mannequin",      # OPEN the mannequin (tx 0x010f) — just look
        "DD-idle-mannequin-open", # leave it open ~5s, then close it
        "DE-walk-away",           # walk well out of range ~6s
        "DF-walk-back",           # walk back, stand still ~6s — is anything re-sent?
        "DG-logout",
    ],
    # MANNEQUIN OUTFITS: a mannequin (item id 438) is in the object stream but the
    # CLOTHES it wears are NOT separate objects — they're its outfit state, sent so
    # the client can render the costume. Find which message carries the worn item
    # ids. Two cases, like signs/vending:
    #   (a) PASSIVE on entry — the costume ships when the realm/entity loads (a
    #       per-mannequin message keyed by its guid, maybe rx 0x0005 player-state
    #       style, or an entity-churn type 0x0044/0x0072/0x0073).
    #   (b) ON AIM/OPEN — only when you query (tx 0x0014) or open (tx 0x010f) it.
    # Do it in the realm that HAS dressed mannequins. WRITE DOWN one garment each
    # mannequin wears (e.g. "Santa Hat") — that name -> id (names.json) is the
    # needle to grep the capture:  python cc_findval.py <cap>.jsonl <that id>
    # Stand STILL around each step so the costume frames aren't buried in movement.
    "mannequin": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~5s wherever you start
        "Q0-goto-mannequin-realm",# travel to the realm with dressed mannequins
        "Q1-idle-see-mannequins", # stand PERFECTLY still ~10s so costumes load
        "Q2-aim-mannequin",       # aim at a DRESSED mannequin — NOTE one item worn
        "Q3-open-mannequin",      # open/click it — just look, change nothing
        "Q4-idle-open",           # leave it ~5s, then close
        "Q5-aim-open-second",     # a DIFFERENT mannequin (note one item it wears)
        "Q6-idle-after",          # stand still ~5s
        "Q7-walk-away-back",      # walk out of range and back — resent on approach?
        "Q8-logout",
    ],
    # WHISPER (private message): decode BOTH directions of the /whisper feature so
    # the bot can answer people privately instead of in public chat. Two unknowns
    # to pin: (1) the SEND format — when you whisper someone, is the recipient
    # addressed by NAME or by their 16-byte GUID, and on which tx type? (2) the
    # RECEIVE format — when someone whispers YOU, is it a new rx type, or a variant
    # of chat (0x000c) / server-notice (0x000d)? Does the incoming frame carry the
    # sender's GUID (so the bot can whisper back) or only a display name?
    #
    # You need a SECOND account (your main) that can whisper this one back — have
    # it logged in on another device/window. Attach cc_capture to THIS (bot) client
    # only. Use the UNIQUE marker strings below verbatim so the fields pin instantly.
    # Run with --plaintext. Analyse:
    #   python cc_findval.py <cap>.jsonl WHISPEROUT771   # pins the SEND text+type
    #   python cc_findval.py <cap>.jsonl WHISPERIN991    # pins the RECEIVE text+type
    #   grep the tx frames for the recipient NAME and for their 32-hex GUID — which
    #     one appears tells us if 'send' targets by name or by GUID.
    #   compare the rx whisper's type byte to 0x000c (chat) / 0x000d (notice).
    # Capture #1 (20260809-175448) SOLVED the SEND path, byte-exact:
    #   /whisper <msg> goes as plain tx 0x000c -> server replies rx 0x00ba MENU
    #   ("Whisper to Who?", u32 menu_id, u8 real-count, then name rows) -> click =
    #   tx 0x00ba + u32 menu_id + u8 index -> server echoes rx 0x000c (own guid,
    #   text "\x10c(.6,.6,.6)(WHISPER)\n<msg>"). STILL MISSING, so this pass targets:
    #   (A) a TRUE INBOUND whisper (another player -> us): rx type + does it carry
    #       the sender's GUID (to reply) and/or name? tag "(From X)"?
    #   (B) the DIRECT send form: does "/whisper <name> <msg>" (name inline) skip the
    #       menu (tx 0x000c only, no 0x00ba round-trip)? If yes the bot never touches
    #       the picker. Also test "/w <name> <msg>" and reply "/r <msg>".
    # Have the OTHER account whisper THIS one FIRST and for sure. Run --plaintext.
    "whisper": [
        "00-startup",
        "01-login",               # log in on the BOT account (the alt)
        "02-idle-in-world",       # settle ~6s; do not move or type
        "W0-idle-before",         # stand PERFECTLY still ~6s (clean baseline)
        "W1-receive-inbound",     # OTHER account whispers THIS one: WHISPERIN991 (do this FIRST, for sure)
        "W2-idle-after-inbound",  # stand still ~6s so the inbound frame lands clean
        "W3-reply-r",             # type "/r WHISPERREPLY55" (reply-to-last) — does it send?
        "W4-idle-after-r",        # stand still ~5s
        "W5-direct-whisper",      # type "/whisper <that name> WHISPERDIRECT77" (name INLINE) — menu or not?
        "W6-idle-after-direct",   # stand still ~5s
        "W7-direct-w-short",      # type "/w <that name> WHISPERW88" (short alias) — does it work?
        "W8-menu-whisper",        # type "/whisper WHISPERMENU99" (NO name) then pick them in the popup
        "W9-logout",
    ],
    # TRADE (two-player secure trade): the unmapped mechanism the buy-order bot
    # needs. This ONE flow carries both halves of the bot's job — a player
    # DEPOSITING cubits (player -> bot) and later COLLECTING (bot -> player: the
    # item + leftover cubits) — plus the CANCEL path (failed/cancelled orders).
    # Unknowns to pin:
    #   (1) INITIATE — how is a trade requested? By NAME or 16-byte GUID, on which
    #       tx type? And the INBOUND request the bot must accept: does it carry the
    #       requester's GUID (so the bot can key the deposit to that player)?
    #   (2) WINDOW — the open/state messages: each side's staked ITEMS (item id +
    #       qty, like inventory 0x000e) and staked CUBITS (an amount field).
    #   (3) STAKE UPDATES — adding/removing an item or changing the cubit amount:
    #       one message per change, or a whole-window resync?
    #   (4) CONFIRM — the ready/accept handshake. Does one side confirming LOCK the
    #       window? Does it commit only when BOTH have confirmed?
    #   (5) COMMIT — completion frames: inventory change (cf. rx 0x0037) and the
    #       cubit-balance change on BOTH sides.
    #   (6) CANCEL — the abort path (either side backs out).
    #
    # You need a SECOND account (your main) trading with THIS (bot) account.
    # Attach cc_capture to the BOT client only, and run with --plaintext.
    # BEFORE you start: write down BOTH accounts' exact Cubit counts off the HUD.
    # Use these UNIQUE, easy-to-grep markers so the fields pin instantly:
    #   * the PLAYER stakes exactly 1337 cubits (the deposit amount)
    #   * the BOT stakes a KNOWN item — write its in-game name down (e.g. one whose
    #     id you can read from names.json) so its id is a needle
    #   * on the collection leg the BOT also stakes exactly 42 leftover cubits
    # Stand PERFECTLY STILL around each step so trade frames aren't buried in
    # movement. Analyse:
    #   python cc_findval.py <cap>.jsonl 1337   # where the deposit amount travels
    #   python cc_findval.py <cap>.jsonl 42     # the leftover-cubit field
    #   python cc_findval.py <cap>.jsonl <the bot item's type_id>  # staked item
    #   grep the tx/rx frames for the OTHER account's NAME and its 32-hex GUID —
    #     which appears in the request/window tells us how to identify the payer.
    #   list every NEW tx/rx type byte not already in SCHEMA.md — that is the trade
    #     message family; compare the commit frame to rx 0x0037 (inventory changed).
    "trade": [
        "00-startup",
        "01-login",               # log in on the BOT account (the alt)
        "02-idle-in-world",       # settle ~6s; do not move or type
        "T0-idle-before",         # stand PERFECTLY still ~6s. NOTE both Cubit counts.
        "T1-receive-request",     # OTHER account requests a trade with the BOT (do this first)
        "T2-accept-open",         # accept it — the trade WINDOW opens (capture the open)
        "T3-idle-window-open",    # stand still ~5s with the empty window open
        "T4-player-stake-1337",   # PLAYER puts exactly 1337 cubits in — the DEPOSIT
        "T5-idle-after-deposit",  # stand still ~5s so the stake frame lands clean
        "T6-bot-stake-item",      # BOT puts a KNOWN item in — write its name down
        "T7-bot-stake-42",        # BOT adds exactly 42 cubits (the leftover leg)
        "T8-idle-both-staked",    # stand still ~5s
        "T9-first-confirm",       # ONE side clicks confirm/ready — does it lock?
        "TA-second-confirm",      # OTHER side confirms — the trade COMMITS
        "TB-idle-after-commit",   # stand still ~6s. NOTE both NEW Cubit counts.
        "TC-second-request",      # start a SECOND trade (either side requests)
        "TD-stake-then-cancel",   # stake something, then CANCEL midway — the abort path
        "TE-idle-after-cancel",   # stand still ~5s so the cancel frame lands clean
        "TF-logout",
    ],
    # COLOURED PUBLIC CHAT: determine whether a player's coloured line is an
    # ordinary 0x000c carrying DLE+c(r,g,b), a different message type, or a
    # client-side effect accompanied by an empty 0x000c. Capture on a RECEIVING
    # official client. The sender must use these exact marker strings so a text
    # search can find them even if the enclosing packet type is unexpected.
    # Press F9 immediately before each requested send, then wait ~3 seconds.
    "colourchat": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # receiver and Vendigo stand still ~6s
        "C0-idle-before",         # clean baseline; nobody chats or moves
        "C1-vendigo-plain",       # Vendigo sends plain: VPLAIN731
        "C2-idle-after-plain",    # wait ~3s
        "C3-vendigo-red",         # same technique, one colour: VCOLORRED742
        "C4-idle-after-red",      # wait ~3s
        "C5-vendigo-blue",        # different colour: VCOLORBLUE853
        "C6-vendigo-multicolour", # multiple colours: VRAINBOW964
        "C7-vendigo-empty-trick", # repeat the exact action that produced empty chat
        "C8-vendigo-leave",       # Vendigo leaves only after F9 reaches this step
        "C9-idle-after-leave",    # receiver stands still ~6s
        "CA-logout",
    ],
    # PLACE A SIGN: decode tx 0x000b (place) + tx 0x001c (hotbar select). The
    # place frame's front bytes are player-pos + facing + selected-item, so to
    # isolate the TARGET-BLOCK coords, STAND IN ONE SPOT and place several signs
    # at different blocks WITHOUT MOVING between them. Do it in YOUR OWN realm
    # with a stack of signs in the hotbar. Analyse by diffing the 0x000b frames:
    #   python cc_findval.py <capture>.jsonl <bx>   # each placed block's coord
    # (note each spot). The one field that changes ONLY with the block you aim at
    # = the coords; everything constant across all three = the sign type/item.
    "placesign": [
        "00-startup",
        "01-login",
        "P0-idle-own-realm",      # stand PERFECTLY still ~6s in your OWN realm
        "P1-select-sign",         # select the SIGN in your hotbar (do ONLY this)
        "P2-place-sign-1",        # WITHOUT MOVING, place a sign 1 block ahead — note where
        "P3-place-sign-2",        # still not moving, place another farther — note where
        "P4-place-sign-3",        # a third at another block — note where
        "P5-write-last-sign",     # write UNIQUE text on the last one: SIGNPLACE7788
        "P6-logout",
    ],
    # How does the game JOIN a realm from the in-game REALM BROWSER (search a
    # name, click Go/Visit) — the way that does NOT relaunch the game or use a
    # browser Share link? Teleport (0x0089) is confirmed player-only (no handoff
    # for a realm GUID) and 0x000e can't cross backends, so the realm-browser
    # "go to realm X" must be its own message on the live socket. With the game
    # already running and cc_capture attached, drive the realm browser and
    # capture the search query + the join. Then find the realm GUID:
    #   python cc_findval.py <capture>.jsonl <the 32-hex realm-reg guid>
    # (Example's Collection = f048fd943100d4c5b23d74dc42cde7de) and note which
    # tx message carries it — that's the join builder to add. Also grep the tx
    # frames for the realm NAME string (the search-query message).
    "realmjoin": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~6s in whatever realm you start in
        "B0-idle-before-search",  # stand PERFECTLY still ~6s — clean baseline
        "B1-open-realm-browser",  # open the in-game realm browser/search panel
        "B2-search-name",         # type the search term — note the EXACT text
        "B3-idle-see-results",    # stand still ~5s while the result list shows
        "B4-click-join-realm",    # click Go/Visit on Example's Collection
        "B5-idle-after-join",     # stand still ~10s in the realm it drops you into
        "B6-search-join-second",  # search + join a DIFFERENT realm (note its name)
        "B7-idle-after-join-2",   # stand still ~10s (two samples pin the field)
        "B8-logout",
    ],
    # How does the client list the realms YOU OWN (by your player GUID)? The
    # name-search (tx 0x00c8 -> rx 0x00e1) is a substring match on realm NAME and
    # carries no owner, so it can't answer "my realms". There must be a separate
    # "list my realms" request keyed by the player GUID (the Realms button / your
    # home realm's realm picker). Attach, open that screen, capture it, then:
    #   python cc_findval.py <capture>.jsonl <your player guid>   # find the tx
    # and read the reply's markup/list for your realm names + GUIDs.
    "myrealms": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~6s
        "M0-idle-before-open",    # stand PERFECTLY still ~6s — clean baseline
        "M1-open-my-realms",      # open the screen that lists YOUR realms
        "M2-idle-see-list",       # stand still ~10s while your realm list shows
        "M3-scroll-or-refresh",   # scroll/refresh the list if it's long (optional)
        "M4-logout",
    ],
    "unfriend": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~5s
        "50-open-friends",        # open the friends panel
        "51-friend-nonfriend",    # friend someone NOT already on your list (note EXACT name)
        "52-idle-check-guid",     # STAND STILL ~6s — does their GUID/entry appear?
        "53-unfriend",            # UNFRIEND that same person (note name)
        "54-idle-after-unfriend", # stand still ~5s
        "55-logout",
    ],
    # CASH REGISTER: how does the official client OPEN a cash register's menu?
    # A register is NOT in the object stream (it never appears as a 0x000f/0x0021
    # object, so 0x010f-by-object-guid can't reach it) and it does NOT answer a
    # 0x0014 block query by coordinate (confirmed live — a 9-column x 5-z sweep
    # centred on the register returned nothing). So the OPEN uses some other tx.
    # Pin these unknowns:
    #   (1) OPEN op — which tx type fires when you click the register? Candidates:
    #       0x000a BLOCK_INTERACT (click a block by index), a 0x010f use-object
    #       with a guid we haven't seen, or a wholly new type. Note the FIRST tx
    #       that leaves the moment you click, before any dialog.
    #   (2) TARGET — does that tx carry BLOCK COORDS (u32 bx,by,bz) or a 16-byte
    #       GUID? If coords, they pin the register's REAL block (ours were wrong).
    #       If a guid, where did the client learn it (an earlier rx we ignored)?
    #   (3) REPLY — what does the server send back? A 0x00ca dialog (like vending),
    #       a trade-window open (0x00a8/0x00ae family), or a bespoke menu type?
    #   (4) OWNERSHIP — capture BOTH as the register's OWNER and as a NON-owner
    #       customer if you can; the menu likely differs (manage vs buy/trade).
    # Do it in the realm that HAS the register. Stand PERFECTLY STILL and click it
    # exactly once per step so the open frames aren't buried in movement. Analyse:
    #   python cc_decode.py <capture>.jsonl                 # -> decoded frames
    #   list every tx type in the 1-2 frames right after each click; the new/odd
    #     one is the OPEN. Then read its body: 12 bytes of u32 coords vs a 16-byte
    #     guid tells target-by-coord from target-by-guid.
    #   python cc_findval.py <capture>.jsonl 49   # bx guess; also try 15, 92, 93
    #   grep the rx right after for type 0x00ca (dialog) / 0x00a8 (trade) bytes.
    "register": [
        "00-startup",
        "01-login",
        "02-idle-in-world",       # settle ~6s wherever you spawn; do not move
        "R0-goto-register-realm", # travel to the realm that HAS the cash register
        "R1-idle-near-register",  # stand PERFECTLY still ~6s right next to it (clean baseline)
        "R2-open-register",       # CLICK the register ONCE to open its menu — just look
        "R3-idle-menu-open",      # leave the menu open ~5s (capture what it shows), then note it
        "R4-close-register",      # close/cancel the menu — change NOTHING, buy NOTHING
        "R5-idle-after-close",    # stand still ~5s so the close frame lands clean
        "R6-open-again",          # open it a SECOND time (confirms the open op is repeatable)
        "R7-idle-second-open",    # stand still ~5s, then close again
        "R8-walk-away",           # walk well OUT of range ~6s (does anything re-send?)
        "R9-logout",
    ],
}

VK = {"F7": 0x76, "F8": 0x77, "F9": 0x78}


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------

def load_secrets(game_dir):
    """Pull credential values out of settings.txt so we can mask them."""
    path = os.path.join(game_dir, "sandbox", "settings.txt")
    keys = ("System.Username", "System.Userpassword", "System.Token",
            "Game.Username", "Game.Password")
    secrets = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k in keys and len(v) >= 3:
                    secrets.append((k, v))
    except OSError:
        pass
    return secrets


def build_patterns(secrets):
    """ASCII + UTF-16LE byte patterns for each secret value."""
    pats = []
    for name, val in secrets:
        for enc in ("utf-8", "utf-16-le"):
            try:
                b = val.encode(enc)
            except UnicodeError:
                continue
            if len(b) >= 3:
                pats.append((name, b))
    # longest first so overlapping values redact cleanly
    pats.sort(key=lambda t: len(t[1]), reverse=True)
    return pats


def redact(payload, patterns):
    """Replace secret byte runs with 0xAA fill. Length-preserving."""
    hits = []
    for name, pat in patterns:
        start = 0
        while True:
            i = payload.find(pat, start)
            if i < 0:
                break
            payload = payload[:i] + (b"\xaa" * len(pat)) + payload[i + len(pat):]
            hits.append(name)
            start = i + len(pat)
    return payload, hits


# --------------------------------------------------------------------------
# hexdump
# --------------------------------------------------------------------------

def hexdump(data, indent="    "):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<47}"
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{indent}{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(out)


# --------------------------------------------------------------------------
# action marker (global hotkeys, no window focus needed)
# --------------------------------------------------------------------------

class ActionTracker:
    def __init__(self, actions):
        self.actions = actions
        self.idx = 0
        self.lock = threading.Lock()
        self._stop = threading.Event()

    @property
    def label(self):
        with self.lock:
            return self.actions[self.idx]

    def show(self):
        cur = self.actions[self.idx]
        nxt = self.actions[self.idx + 1] if self.idx + 1 < len(self.actions) else "(end)"
        print(f"\n  >> NOW: [{self.idx:02d}] {cur}"
              f"\n     next (F9): {nxt}\n", flush=True)

    def start(self):
        t = threading.Thread(target=self._poll, daemon=True)
        t.start()
        self.show()

    def stop(self):
        self._stop.set()

    def _poll(self):
        gas = ctypes.windll.user32.GetAsyncKeyState
        # Prime: clear any stale "pressed since last call" bits.
        for vk in VK.values():
            gas(vk)
        while not self._stop.is_set():
            if gas(VK["F9"]) & 0x0001:
                with self.lock:
                    if self.idx + 1 < len(self.actions):
                        self.idx += 1
                self.show()
            if gas(VK["F8"]) & 0x0001:
                with self.lock:
                    if self.idx > 0:
                        self.idx -= 1
                self.show()
            if gas(VK["F7"]) & 0x0001:
                self.show()
            time.sleep(0.04)


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

def preflight(game_dir):
    problems = []
    exe = os.path.join(game_dir, GAME_EXE)
    if not os.path.isfile(exe):
        problems.append(f"game exe not found: {exe}")
    dll = os.path.join(game_dir, "libnopoll.dll")
    if not os.path.isfile(dll):
        problems.append(f"libnopoll.dll not found: {dll}")
    if not os.path.isfile(AGENT):
        problems.append(f"agent script not found: {AGENT}")

    print(f"  frida        {frida.__version__}")
    print(f"  python       {sys.version.split()[0]} "
          f"({'64' if sys.maxsize > 2**32 else '32'}-bit host)")
    print(f"  target       {exe}  (32-bit x86)")

    steam = False
    try:
        import subprocess
        r = subprocess.run(["tasklist", "/FI", "IMAGENAME eq steam.exe"],
                           capture_output=True, text=True, timeout=10)
        steam = "steam.exe" in r.stdout.lower()
    except Exception:
        pass
    print(f"  steam        {'running' if steam else 'NOT RUNNING'}")
    if not steam:
        problems.append("Steam is not running -- the game refuses to start without it "
                        "('Steam needs to be loaded for Cubic Castles to function.')")
    return problems


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def _list_game_procs():
    """Running Cubic.exe processes, across frida API variants (the module-level
    enumerate_processes() isn't present on every build — go via the device)."""
    try:
        procs = frida.get_local_device().enumerate_processes()
    except Exception:
        try:
            procs = frida.enumerate_processes()
        except Exception:
            return []
    return [p for p in procs if p.name.lower() == GAME_EXE.lower()]


def main():
    ap = argparse.ArgumentParser(description="Cubic Castles WebSocket capture")
    ap.add_argument("--game-dir", default=GAME_DIR)
    ap.add_argument("--attach", action="store_true",
                    help="attach to a running Cubic.exe instead of spawning "
                         "(will miss the login handshake)")
    ap.add_argument("--pid", type=int, default=None,
                    help="attach to this exact process id (use with two game "
                         "clients running at once; see --list). Implies --attach.")
    ap.add_argument("--tag", default=None,
                    help="label added to the output filenames, e.g. --tag botname, "
                         "so two simultaneous captures don't collide")
    ap.add_argument("--list", action="store_true",
                    help="list running Cubic.exe process ids and exit (pick the "
                         "pid for each account, then run one capture per --pid)")
    ap.add_argument("--no-redact", action="store_true",
                    help="do not mask stored credentials in captured payloads")
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--duration", type=float, default=None,
                    help="stop automatically after N seconds (smoke-testing the hooks)")
    ap.add_argument("--kill-on-exit", action="store_true",
                    help="terminate the spawned game process when capture stops")
    ap.add_argument("--checklist", choices=sorted(CHECKLISTS), default="full",
                    help="which F9 action list to use ('teleport' skips straight "
                         "to the friends-list steps)")
    ap.add_argument("--backtrace", type=int, default=0, metavar="N",
                    help="backtrace the first N outbound sends to locate the "
                         "encryption layer inside Cubic.exe (try 5)")
    ap.add_argument("--plaintext", action="store_true",
                    help="hook the XXTEA framer (Cubic.exe+0x11362c) to capture "
                         "cleartext messages and dump the 128-bit key")
    ap.add_argument("--cipher-trace", type=int, default=0, metavar="N",
                    help="trace the first N encrypted sends at the framer, XXTEA "
                         "core, append calls, and final send callsite")
    args = ap.parse_args()

    if args.list:
        procs = [p for p in _list_game_procs()]
        if not procs:
            print(f"no {GAME_EXE} process running.")
            return 0
        print(f"running {GAME_EXE} instances (attach one capture per pid):")
        for p in procs:
            print(f"  pid {p.pid}")
        print(f"\nexample (two terminals, one per account):")
        print(f"  python cc_capture.py --pid {procs[0].pid} --plaintext "
              f"--tag acctA --checklist trade")
        if len(procs) > 1:
            print(f"  python cc_capture.py --pid {procs[1].pid} --plaintext "
                  f"--tag acctB --checklist trade")
        return 0

    print("=" * 72)
    print(" Cubic Castles - Stage 2 capture")
    print("=" * 72)

    problems = preflight(args.game_dir)
    if problems:
        print("\nPREFLIGHT FAILED:")
        for p in problems:
            print("  - " + p)
        return 1

    # --- redaction setup ---
    patterns = []
    if not args.no_redact:
        secrets = load_secrets(args.game_dir)
        patterns = build_patterns(secrets)
        if secrets:
            print(f"  redaction    ON  ({', '.join(k for k, _ in secrets)})")
        else:
            print("  redaction    ON  (no stored credentials found in settings.txt --"
                  " nothing to mask yet)")
    else:
        print("  redaction    OFF  <-- payloads will contain credentials in cleartext")

    outdir = args.outdir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "captures")
    os.makedirs(outdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    tag = f"-{re.sub(r'[^A-Za-z0-9_.-]', '_', args.tag)}" if args.tag else ""
    jsonl_path = os.path.join(outdir, f"capture-{stamp}{tag}.jsonl")
    log_path = os.path.join(outdir, f"capture-{stamp}{tag}.log")
    print(f"  output       {jsonl_path}")
    print(f"               {log_path}")

    tracker = ActionTracker(CHECKLISTS[args.checklist])
    counters = {"tx": 0, "rx": 0, "redacted": 0}
    t0 = time.time()

    jsonl = open(jsonl_path, "w", encoding="utf-8")
    logf = open(log_path, "w", encoding="utf-8")

    def write_log(text):
        logf.write(text + "\n")
        logf.flush()

    def on_message(message, data):
        if message["type"] == "error":
            print(f"[agent error] {message.get('description')}", flush=True)
            write_log(f"[agent error] {message.get('description')}")
            return

        p = message.get("payload") or {}
        kind = p.get("type")
        now = time.time()
        rel = now - t0

        if kind == "log":
            print(f"[agent] {p['msg']}", flush=True)
            write_log(f"[agent] {p['msg']}")
            return

        if kind == "conn_new":
            rec = {"t": round(rel, 4), "wall": now, "type": "conn_new",
                   "action": tracker.label,
                   "host_ip": p.get("host_ip"), "host_port": p.get("host_port"),
                   "host_name": p.get("host_name"), "get_url": p.get("get_url"),
                   "protocols": p.get("protocols"), "origin": p.get("origin"),
                   "conn": p.get("conn")}
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            banner = (
                f"\n{'='*72}\n"
                f"CONNECT  t={rel:8.3f}s  action={tracker.label}\n"
                f"  host_ip   : {p.get('host_ip')}\n"
                f"  host_port : {p.get('host_port')}\n"
                f"  host_name : {p.get('host_name')}\n"
                f"  get_url   : {p.get('get_url')}\n"
                f"  protocols : {p.get('protocols')}\n"
                f"  origin    : {p.get('origin')}\n"
                f"{'='*72}"
            )
            print(banner, flush=True)
            write_log(banner)
            return

        if kind == "plaintext":
            plain = data or b""
            hits = []
            if patterns:
                plain, hits = redact(plain, patterns)
            rec = {"t": round(rel, 4), "wall": now, "type": "plaintext",
                   "action": tracker.label, "len": p.get("len"),
                   "layout": p.get("layout"), "hex": plain.hex()}
            if p.get("key_hex"):
                rec["key_hex"] = p["key_hex"]
            if hits:
                rec["redacted"] = sorted(set(hits))
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            if p.get("key_hex"):
                banner = (f"\n{'#'*72}\n"
                          f" XXTEA KEY (128-bit, from [conn+0x14]): {p['key_hex']}\n"
                          f"{'#'*72}")
                print(banner, flush=True)
                write_log(banner)
            arrow = "==>"
            preview = "".join(chr(b) if 32 <= b < 127 else "." for b in plain[:48])
            head = (f"\n[{rel:8.3f}s] {arrow} PLAINTEXT len={p.get('len')} "
                    f"action={tracker.label}"
                    + ("  [REDACTED]" if hits else ""))
            write_log(head)
            write_log(hexdump(plain))
            print(f"[{rel:7.2f}s] {arrow} plain {p.get('len',0):5d}B "
                  f"{tracker.label:<20} {preview}", flush=True)
            return

        if kind == "cipher_stage":
            rec = {"t": round(rel, 4), "wall": now, "type": "cipher_stage",
                   "action": tracker.label}
            rec.update({k: v for k, v in p.items()
                        if k not in ("type", "ts")})
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            snap = p.get("snapshot") or p.get("after") or {}
            detail = []
            if snap.get("len") is not None:
                detail.append(f"len={snap['len']}")
            if p.get("words") is not None:
                detail.append(f"words={p['words']}")
            if p.get("value") is not None:
                detail.append(f"value=0x{p['value']:08x}")
            line = (f"[{rel:7.2f}s] CIPHER {p.get('stage','?'):<14} " +
                    " ".join(detail))
            print(line, flush=True)
            write_log(line)
            return

        if kind == "backtrace":
            rec = {"t": round(rel, 4), "wall": now, "type": "backtrace",
                   "action": tracker.label, "site": p.get("site"),
                   "len": p.get("len"), "frames": p.get("frames")}
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            block = [f"\n{'~'*72}",
                     f"BACKTRACE from {p.get('site')} (len={p.get('len')}) "
                     f"t={rel:.3f}s",
                     "  The immediate caller inside Cubic.exe is the encryption "
                     "layer; hook it to get plaintext."]
            for fr in p.get("frames") or []:
                block.append(f"  -- {fr.get('mode')} --")
                for i, s in enumerate(fr.get("stack") or []):
                    mod = s.get("module") or "?"
                    off = s.get("offset") or ""
                    sym = f"  {s['sym']}" if s.get("sym") else ""
                    block.append(f"    #{i:<2} {mod}{off}{sym}")
            block.append("~" * 72)
            text = "\n".join(block)
            print(text, flush=True)
            write_log(text)
            return

        if kind == "conn_state":
            rec = {"t": round(rel, 4), "wall": now, "type": "conn_state",
                   "action": tracker.label, "fn": p.get("fn"),
                   "conn": p.get("conn"), "value": p.get("value")}
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            line = (f"[{rel:7.2f}s] STATE {p.get('fn')}({p.get('conn')}) "
                    f"-> {p.get('value')}")
            print(line, flush=True)
            write_log(line)
            return

        if kind == "conn_close":
            rec = {"t": round(rel, 4), "wall": now, "type": "conn_close",
                   "action": tracker.label, "conn": p.get("conn")}
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            write_log(f"\nCLOSE    t={rel:8.3f}s  conn={p.get('conn')}")
            return

        if kind == "conn_dump":
            regions = p.get("regions") or []
            rec = {"t": round(rel, 4), "wall": now, "type": "conn_dump",
                   "action": tracker.label, "regions": regions}
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()
            line = (f"[{rel:7.2f}s] CONN_DUMP {len(regions)} region(s) captured "
                    f"(offline key recovery: diag_keyfromdump.py)")
            print(line, flush=True)
            write_log(line)
            return

        if kind == "frame":
            payload = data or b""
            hits = []
            if patterns:
                payload, hits = redact(payload, patterns)
                if hits:
                    counters["redacted"] += 1

            direction = p["dir"]
            counters[direction] += 1
            action = tracker.label

            rec = {
                "t": round(rel, 4),
                "wall": now,
                "type": "frame",
                "dir": direction,
                "action": action,
                "len": p["len"],
                "fin": p.get("fin", 1),
                "conn": p.get("conn"),
                "hex": payload.hex(),
            }
            if hits:
                rec["redacted"] = sorted(set(hits))
            jsonl.write(json.dumps(rec) + "\n")
            jsonl.flush()

            arrow = "-->" if direction == "tx" else "<--"
            head = (f"\n[{rel:8.3f}s] {arrow} {direction.upper()} "
                    f"len={p['len']} fin={p.get('fin', 1)} action={action}"
                    + ("  [REDACTED: " + ",".join(sorted(set(hits))) + "]" if hits else ""))
            write_log(head)
            write_log(hexdump(payload))

            preview = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:48])
            print(f"[{rel:7.2f}s] {arrow} {direction} {p['len']:5d}B "
                  f"{action:<20} {preview}", flush=True)
            return

    # --- launch / attach ---
    exe = os.path.join(args.game_dir, GAME_EXE)
    pid = None
    spawned = False
    try:
        if args.pid is not None:
            print(f"\n  attaching to Cubic.exe pid {args.pid} ...")
            session = frida.attach(args.pid)
        elif args.attach:
            procs = _list_game_procs()
            if len(procs) > 1:
                print(f"\nERROR: {len(procs)} Cubic.exe instances are running "
                      f"({', '.join(str(p.pid) for p in procs)}). Attaching by "
                      f"name is ambiguous — pick one with --pid (see --list).")
                return 1
            print("\n  attaching to running Cubic.exe ...")
            session = frida.attach(GAME_EXE)
        else:
            print("\n  spawning Cubic.exe (suspended) ...")
            pid = frida.spawn([exe], cwd=args.game_dir)
            spawned = True
            session = frida.attach(pid)
    except frida.ProcessNotFoundError:
        print("ERROR: Cubic.exe is not running (use spawn mode, i.e. drop --attach)")
        return 1
    except Exception as exc:
        print(f"ERROR: could not start/attach: {exc}")
        return 1

    with open(AGENT, "r", encoding="utf-8") as fh:
        source = fh.read()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print("  agent loaded.")

    if args.backtrace or args.plaintext or args.cipher_trace:
        exports = getattr(script, "exports_sync", None) or script.exports
        if args.backtrace:
            try:
                exports.set_backtrace_budget(args.backtrace)
                print(f"  backtracing first {args.backtrace} outbound sends "
                      f"(locating the crypto layer)")
            except Exception as exc:
                print(f"  WARNING: could not enable backtracing: {exc}")
        if args.plaintext:
            try:
                r = exports.enable_plaintext()
                print(f"  plaintext hook: {r}")
            except Exception as exc:
                print(f"  WARNING: could not enable plaintext capture: {exc}")
        if args.cipher_trace:
            try:
                r = exports.enable_cipher_trace(args.cipher_trace)
                print(f"  cipher trace: {r} (budget={args.cipher_trace})")
            except Exception as exc:
                print(f"  WARNING: could not enable cipher tracing: {exc}")

    if spawned:
        frida.resume(pid)
        print("  process resumed.\n")

    print("-" * 72)
    print(" F9 = next action    F8 = previous    F7 = show position")
    print(" Ctrl+C here when finished (or just close the game).")
    print("-" * 72)

    tracker.start()

    deadline = (time.time() + args.duration) if args.duration else None
    try:
        while True:
            time.sleep(0.5)
            if deadline and time.time() >= deadline:
                print(f"\n  duration limit ({args.duration}s) reached.")
                break
            if not session.is_detached:
                continue
            print("\n  process detached.")
            break
    except KeyboardInterrupt:
        print("\n  stopping ...")
    finally:
        tracker.stop()
        try:
            session.detach()
        except Exception:
            pass
        if args.kill_on_exit and pid is not None:
            try:
                frida.kill(pid)
                print("  game process terminated.")
            except Exception:
                pass
        jsonl.close()
        summary = (f"\n{'='*72}\n"
                   f" frames: tx={counters['tx']} rx={counters['rx']} "
                   f"redacted={counters['redacted']}\n"
                   f" duration: {time.time() - t0:.1f}s\n"
                   f"{'='*72}")
        write_log(summary)
        logf.close()
        print(summary)
        print(f"\n  {jsonl_path}\n  {log_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
