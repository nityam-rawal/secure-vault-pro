# Secure Vault Pro Companion

This Chrome/Edge extension exports browser history into a local JSON file for the Secure Vault Pro web app.

## Load it

1. Open `chrome://extensions` or `edge://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the `extension/` folder from this repo

## What it does

- Reads browser history only after the extension is installed and granted permission
- Shows a quick local preview of suspicious history patterns
- Downloads a JSON file that the Secure Vault Pro web app can import in the `Visited Site Risk Review` panel
- Opens your configured Secure Vault Pro app URL directly from the popup

## What it does not do

- It does not upload history by itself
- It does not bypass browser permissions
- It does not scrape other sites or hidden account data
