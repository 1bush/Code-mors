"""Local-only pairing regression. Requires web :5173 and relay :7000."""
import asyncio
from playwright.async_api import async_playwright, expect

BASE = 'http://localhost:5173'

async def enter(browser, errors, url=BASE):
    context = await browser.new_context()
    page = await context.new_page()
    page.set_default_timeout(8000)
    page.on('pageerror', lambda error: errors.append(str(error)))
    await page.goto(BASE, wait_until='domcontentloaded')
    await page.locator('#mo-pin.on').wait_for()
    for _ in range(4):
        await page.locator('#pin-pad .key').filter(has_text='0').click()
    await expect(page.locator('#mo-pin')).to_be_hidden()
    return page

async def submit(page, invite):
    # Manual input is the same handler used by the camera decoder.
    await page.evaluate("document.querySelector('#mo-scan').classList.add('on')")
    await page.locator('#scan-manual').fill(invite)
    await page.locator('#mo-scan button').filter(has_text='LINK').click()

async def main():
    errors = []
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            a, b, c = [await enter(browser, errors) for _ in range(3)]
            await a.click('#btn-qr')
            await a.wait_for_function("document.querySelector('#qr-code').value.startsWith('http')")
            invite = await a.locator('#qr-code').input_value()
            # Verify the actual QR pixels encode this exact link.
            decoded = await a.evaluate('''() => {
                const c=document.querySelector('#qr-canvas');
                const image=c.getContext('2d').getImageData(0,0,c.width,c.height);
                return jsQR(image.data,image.width,image.height)?.data;
            }''')
            assert decoded == invite, 'QR pixels differ from invite link'
            await a.evaluate('closeModal()')
            await submit(b, invite)
            ghost_a, ghost_b = await a.evaluate('S.ghost'), await b.evaluate('S.ghost')
            await b.wait_for_function('name => S.cur === name', arg=ghost_a)
            await a.wait_for_function('name => S.cur === name', arg=ghost_b)
            await expect(b.locator('#mo-scan')).to_be_hidden()
            print('PASS: invitation connects two clean profiles', flush=True)
            for sender, receiver, text in [(a,b,'request A to B'), (b,a,'reply B to A')]:
                await sender.locator('#minput').fill(text)
                await sender.click('#btn-send')
                await expect(receiver.locator('#mlist')).to_contain_text(text)
            print('PASS: message round-trip A -> B -> A', flush=True)
            await submit(c, invite)
            await expect(c.locator('#scan-status')).to_contain_text('e përdorur')
            assert await c.evaluate('Object.keys(S.sess).length') == 0
            assert await c.evaluate('S.cur') is None
            print('PASS: same invitation rejected in third clean profile', flush=True)
            assert not errors, errors
            print('PASS: QR pixels verified; no uncaught JavaScript errors', flush=True)
        finally:
            await browser.close()

asyncio.run(main())
