# FAQ

Q: What is it?
<br>A: This is a comprehensive anti-ban-bypass system. Players are checked for their country, proxy/VPN, and local provider bans (ASN bans).

Q: Who is this system for?
<br>A: For advanced server administrators

Q: Is the system fully automatic?
<br>A: Yes and no. It also has manual control tools, since automatic protection can be bypassed if you know how to do it.

Q: Does the system give 100% results?
<br>A: No

# Requirements

- [AMX Mod X](https://github.com/alliedmodders/amxmodx) 1.9 or 1.10 ([Snapshots](https://www.amxmodx.org/downloads-new.php))
- [ReAPI](https://github.com/rehlds/ReAPI)
- Optional AMXX Modules: [Curl](https://github.com/Next21Team/AmxxCurl) / [Grip](https://github.com/In-line/grip) / [IphubClient](https://github.com/Giferns/BypassGuard/blob/master/amxx_modules/)
- MySQL Database (for Supervisor, you may not use it, but it is highly recommended)

# Installation

- Install core plugin `bypass_guard.amxx`
- Set up the configuration file `addons/amxmodx/configs/plugins/plugin-bypass_guard.cfg`
- Depending on `bypass_guard_country_check_mode` cvar value, set up `addons/amxmodx/configs/bypass_guard/allowed_countries.ini` or `banned_countries.ini`
- Install data provider plugin `bg_provider_iphubclient.amxx`
- Install `modules/iphubclient_amxx_i386.so` (for linux) or `modules/iphubclient_amxx.dll` (for windows)
- Go to [iphub.info](https://iphub.info/), register, get free API key. It is recommended to make 5 or more personal API keys for every CS server. You can get one API key for one account, so register multiple accounts using vpn and [temp-mail.org](https://temp-mail.org/), or just wait (you can register 3 accounts every hour)
- Set up API keys in `addons/amxmodx/configs/bypass_guard/iphub_api_keys.ini`
- Install `bg_supervisor.amxx`
- Set up the configuration file `addons/amxmodx/configs/plugins/plugin-bg_supervisor.cfg`
- Start or restart server for the first run of newly installed plugins
- Type `amxx plugins` into server console and check plugins status, that sound be `running` for all three plugins
- Check `amxmodx/logs` and `amxmodx/logs/bypass_guard` for the presence of error logs

# Console commands

# Work scheme

![work scheme](https://github.com/user-attachments/assets/4bccdf8f-779d-49c6-8f42-d91929b37eb2)
