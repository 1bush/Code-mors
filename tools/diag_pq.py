"""Diagnoze PQ: gjendja e te dy aneve pas pairing-ut dhe pas nje mesazhi.
Requires web :5173 and relay :7000."""
import asyncio, traceback
from playwright.async_api import async_playwright

BASE = 'http://localhost:5173'

async def enter(browser):
    ctx = await browser.new_context()
    page = await ctx.new_page()
    page.set_default_timeout(20000)
    await page.goto(BASE, wait_until='domcontentloaded')
    await page.locator('#mo-pin.on').wait_for()
    for _ in range(4):
        await page.locator('#pin-pad .key').filter(has_text='0').click()
    await page.locator('#mo-pin').wait_for(state='hidden')
    return page

async def state(p):
    return await p.evaluate("""() => { const n=S.cur; const s=n?S.sess[n]:null; const br=document.getElementById('breach'); return {
        cur:n, pqModule:!!S.pq, pqpk:(S.myPQpk||'').length, pqDone:s?s.pqDone:null,
        queued:(s&&s.pqQueue?s.pqQueue.length:0), breach:(br?br.textContent:'')||'', breachShown:(br?br.style.display:''),
        mlist:(document.getElementById('mlist')||{}).innerText||''
    }; }""")

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        a = b = None
        try:
            a, b = await enter(browser), await enter(browser)
            await a.click('#btn-qr')
            await a.wait_for_function("document.querySelector('#qr-code').value.startsWith('http')")
            invite = await a.locator('#qr-code').input_value()
            await a.evaluate('closeModal()')
            await b.evaluate("document.querySelector('#mo-scan').classList.add('on')")
            await b.locator('#scan-manual').fill(invite)
            await b.locator('#mo-scan button').filter(has_text='LINK').click()
            gb = await b.evaluate('S.ghost')
            ga = await a.evaluate('S.ghost')
            await a.wait_for_function('n => S.cur === n', arg=gb)
            await b.wait_for_function('n => S.cur === n', arg=ga)
            print('A after pairing:', await state(a), flush=True)
            print('B after pairing:', await state(b), flush=True)
            await a.locator('#minput').fill('ping-A2B')
            await a.click('#btn-send')
            await a.wait_for_timeout(6000)
            print('A after send:', await state(a), flush=True)
            print('B after send:', await state(b), flush=True)
            print('A blog:', (await a.evaluate("document.getElementById('blog').textContent")).replace('\n', ' ')[-260:], flush=True)
            print('B blog:', (await b.evaluate("document.getElementById('blog').textContent")).replace('\n', ' ')[-260:], flush=True)
        except Exception:
            traceback.print_exc()
            for tag, pg in (('A', a), ('B', b)):
                if pg:
                    try:
                        print(tag, 'state:', await state(pg), flush=True)
                    except Exception as e:
                        print(tag, 'state failed:', e, flush=True)
        finally:
            await browser.close()

asyncio.run(main())