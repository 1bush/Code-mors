import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()
        page.set_default_timeout(8000)
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        await page.goto('http://localhost:5173', wait_until='domcontentloaded')
        await page.locator('#mo-pin.on').wait_for()
        for _ in range(4):
            await page.locator('#pin-pad .key').filter(has_text='0').click()
        await page.locator('#mo-pin').wait_for(state='hidden')
        result = await page.evaluate('''async () => {
          try {
            const peer = await genKP();
            await makeSession(S.myKP, await expPub(peer));
            return {ok:true};
          } catch(e) { return {ok:false, error:e.stack}; }
        }''')
        print('PIN entry: PASS', flush=True)
        print('Session:', result, 'Page errors:', errors, flush=True)
        await browser.close()
        assert result['ok'], result.get('error')
        assert not errors, errors

asyncio.run(main())
