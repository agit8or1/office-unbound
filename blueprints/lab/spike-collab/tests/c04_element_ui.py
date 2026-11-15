#!/usr/bin/env python3
"""C04 Element Web UI smoke (headless Chromium): bob signs in via Element -> MAS -> Keycloak, creates a room, posts a message,
and the message is visible in the timeline. Screenshots go to $OU_SHOTDIR."""
import os
import sys
import time
import uuid

from playwright.sync_api import sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collab_lib as L

SHOTS = os.environ.get("OU_SHOTDIR", "/tmp/claude-1000/-home-administrator/a1d917f8-7438-424e-a57a-793b46deb95e/scratchpad/chat-r")
rep = L.Report("C04 Element Web UI: sign in (OIDC via MAS+Keycloak), create room, send message")
name = "ui-spike-" + uuid.uuid4().hex[:6]
text = "hello from element ui " + uuid.uuid4().hex[:6]
with sync_playwright() as p:
    b = L.browser(p)
    pg = b.new_context(viewport={"width": 1280, "height": 800}).new_page()
    pg.goto(L.ELEMENT + "/", wait_until="domcontentloaded")
    pg.wait_for_selector("text=Sign in", timeout=30000)
    pg.click("text=Sign in")
    t0 = time.time()
    logged = False
    for i in range(60):
        pg.wait_for_timeout(1000)
        u = pg.url
        if u.startswith(L.KC) and pg.query_selector("input[name=username]"):
            L.kc_login(pg, "bob", L.password("bob"))
        elif u.startswith(L.MAS):
            for sel in ("button:has-text('Continue')", "a:has-text('Office Unbound SSO')"):
                e = pg.query_selector(sel)
                if e:
                    e.click()
                    break
        elif u.startswith(L.ELEMENT) and "Account provider" in pg.inner_text("body"):
            pg.click("button:has-text('Continue')")
        elif u.startswith(L.ELEMENT):
            # dismiss crypto/verification dialogs that Element shows after first login
            for sel in ("button:has-text('Skip')", "button:has-text('Not now')", "button:has-text('Cancel')", "button:has-text('Dismiss')"):
                e = pg.query_selector(sel)
                if e and e.is_visible():
                    e.click()
            if pg.query_selector("[aria-label='Add'], [aria-label='Start chat'], [data-testid='room-list']") or "Welcome" in pg.inner_text("body")[:200]:
                logged = True
                break
    pg.screenshot(path=SHOTS + "/element-after-login.png")
    rep.check("Element signed in via MAS/Keycloak", logged, "%.1fs, url=%s" % (time.time() - t0, pg.url.split("#")[0]))
    if logged:
        # create room through the hash route dialog
        pg.goto(L.ELEMENT + "/#/home")
        pg.wait_for_timeout(2000)
        for sel in ("[aria-label='Add']", "[aria-label='Start chat']"):
            e = pg.query_selector(sel)
            if e:
                e.click()
                break
        pg.wait_for_timeout(1000)
        pg.screenshot(path=SHOTS + "/element-menu.png")
        for sel in ("text=New room", "[role=menuitem]:has-text('New room')"):
            e = pg.query_selector(sel)
            if e:
                e.click()
                break
        pg.wait_for_selector("input[label='Name'], input#mx_CreateRoomDialog_name, [name=name], input[type=text]", timeout=15000)
        pg.keyboard.type(name)
        pg.click("button:has-text('Create room')")
        pg.wait_for_selector("[role=textbox][contenteditable], .mx_BasicMessageComposer_input", timeout=30000)
        pg.click("[role=textbox][contenteditable], .mx_BasicMessageComposer_input")
        pg.keyboard.type(text)
        pg.keyboard.press("Enter")
        pg.wait_for_selector("text=" + text, timeout=20000)
        rep.check("room '%s' created and message visible in the timeline" % name, True)
        pg.screenshot(path=SHOTS + "/element-room.png")
    b.close()
rep.finish()
