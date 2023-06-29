/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин может (регулируется кварами):
		* Предоставлять AS-номер
		* Проверять IP-адрес на proxy/VPN
		* Предоставлять название и код страны

	Используемый сервис: https://iphub.info/ (требуется регистрация; вход через прокси, если не открывается)
	Описание API: https://iphub.info/api

	Плюсы:
		* Высокий уровень точности проверки на proxy/VPN
		* Возможность задать несколько ключей

	Минусы:
		* Необходима регистрация
		* Зачастую невнятное описание провайдера при получении AS-номера

	Использование:
		1) Установите модуль IPHub-Client: https://github.com/Hun1eR/IPHub-Client/releases
		1) Зарегистрируйтесь на сервисе и получите бесплатный ключ (используйте прокси, если сайт не открывается)
		2) Пропишите ключ (на новой строке) в конфиг 'iphub_api_keys.ini'
		3) Запустите плагин
		4) Отредактируйте квары плагина в конфиге в 'configs/plugins'
		5) Смените карту, чтобы новые значения кваров вступили в силу
*/

/* История обновлений:
	1.0 (03.05.2019):
		* Открытый релиз
	1.1 (22.11.2021):
		* Уход от логики с кваром-указателем # ключа и OnConfigsExecuted() в сторону localinfo
	1.2 (30.05.2023):
		* Актуализация API
		* Незначительные улучшения
	0.3 (26.06.2023):
		* Добавлена очередь ожидания поступления данных (g_bitDataQueue), дабы избежать двойного обращения к API,
			т.к. запрос гео отправляется сразу в putinserver, а запрос AS чуть позже (пауза по квару bypass_guard_check_delay.
			При этом, если на момент запроса AS информация по гео ещё не поступила в кеш, то будет совершён повторный запрос
*/

new const PLUGIN_VERSION[] = "1.3"

/* ----------------------- */

// Create config with cvars in 'configs/plugins' and execute it?
//
// Создавать конфиг с кварами в 'configs/plugins', и запускать его ?
#define AUTO_CFG

// Max number of API keys. Increase if you need to.
//
// Макс. кол-во API-ключей. Увеличить при необходимости.
const MAX_KEYS = 10

new const KEY_FILE_NAME[] = "iphub_api_keys.ini"

/* ----------------------- */

#include <amxmodx>
#include <iphubclient>
#include <bypass_guard>

#define chx charsmax
#define chx_len(%0) charsmax(%0) - iLen

#define MAX_API_KEY_LEN 64

#define REQUEST_SUCCESSFUL 200
#define KEY_EXPIRED 429

enum _:CHECK_TYPE_ENUM {
	CHECK_TYPE__AS,
	CHECK_TYPE__PROXY,
	CHECK_TYPE__GEO
}

enum _:CHECK_EXT_DATA_STRUCT {
	CHECK_EXT_DATA__TYPE,
	CHECK_EXT_DATA__PLAYER_USERID,
	CHECK_EXT_DATA__IP[MAX_IP_LENGTH],
	CHECK_EXT_DATA__KEY_NUMBER,
	bool:CHECK_EXT_DATA__RETRY,
	CHECK_CACHE__MAX_TRIES
}

// sizes as in iphubclient.inc, see iphub_code and iphub_name
#define IHC_COUNTRY_CODE_LEN 4
#define IHC_COUNTRY_NAME_LEN 32

enum _:CHECK_CACHE_DATA_STRUCT {
	CHECK_CACHE__AS[MAX_AS_LEN],
	CHECK_CACHE__DESC[MAX_DESC_LEN],
	bool:CHECK_CACHE__IS_PROXY,
	CHECK_CACHE__COUNTRY_CODE[IHC_COUNTRY_CODE_LEN],
	CHECK_CACHE__COUNTRY_NAME[IHC_COUNTRY_NAME_LEN]
}

enum _:CVAR_ENUM {
	CVAR__USE_FOR_AS,
	CVAR__USE_FOR_PROXY,
	CVAR__USE_FOR_GEO,
	CVAR__BAN_SUSPICIOUS,
	CVAR__CURRENT_KEY
}

enum (<<=1) {
	DATA_QUEUE__GEO = 1,
	DATA_QUEUE__AS
}

new g_eCvar[CVAR_ENUM]
new bool:g_bPluginEnded
new Trie:g_tCheckExtData
new Trie:g_tCheckCache
new g_szApiKey[MAX_KEYS][MAX_API_KEY_LEN]
new g_iLoadedKeys
new g_bitDataQueue[MAX_PLAYERS + 1]

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: IPHub-Client", PLUGIN_VERSION, "mx?!")

	g_tCheckExtData = TrieCreate()
	g_tCheckCache = TrieCreate()

	bind_pcvar_num( create_cvar("bg_iphubclient_use_for_as", "1",
		.description = "Use this provider for getting AS number?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_AS]
	);

	bind_pcvar_num( create_cvar("bg_iphubclient_use_for_proxy", "1",
		.description = "Use this provider for proxy status checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_PROXY]
	);

	bind_pcvar_num( create_cvar("bg_iphubclient_use_for_geo", "1",
		.description = "Use this provider for country checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_GEO]
	);

	bind_pcvar_num( create_cvar("bg_iphubclient_ban_suspicious", "0",
		.description = "Consider suspicious IPs as proxy (can bring false detections) ?^n\
		Has no effect if 'bg_iphub_use_for_proxy' is set to 0"),
		g_eCvar[CVAR__BAN_SUSPICIOUS]
	);

#if defined AUTO_CFG
	AutoExecConfig()
#endif

	/* --- */

	new szValue[32]; get_localinfo("_bg_ihc_key", szValue, chx(szValue))
	g_eCvar[CVAR__CURRENT_KEY] = str_to_num(szValue)

	func_LoadApiKeys()

	if(g_eCvar[CVAR__CURRENT_KEY] >= g_iLoadedKeys) {
		func_SetCurrentKey(max(0, g_iLoadedKeys - 1))
	}
}

/* ----------------------- */

func_SetCurrentKey(iValue) {
	g_eCvar[CVAR__CURRENT_KEY] = iValue
	set_localinfo("_bg_ihc_key", fmt("%i", iValue))
}

/* ----------------------- */

public BypassGuard_RequestAsInfo(pPlayer, const szIP[], iMaxTries) {
	if(!g_eCvar[CVAR__USE_FOR_AS]) {
		return PLUGIN_CONTINUE
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	// NOTE: 'bg_get_as_by_ip' command depends on this cache (instant return), see main plugin
	if(TrieGetArray(g_tCheckCache, szIP, eCheckCache, sizeof(eCheckCache))) {
		BypassGuard_SendAsInfo( pPlayer, eCheckCache[CHECK_CACHE__AS],
			eCheckCache[CHECK_CACHE__DESC], .bSuccess = true );

		return PLUGIN_HANDLED
	}

	if(g_bitDataQueue[pPlayer] & DATA_QUEUE__GEO) {
		g_bitDataQueue[pPlayer] |= DATA_QUEUE__AS
		return PLUGIN_HANDLED
	}

	func_MakeRequest(pPlayer, szIP, iMaxTries, CHECK_TYPE__AS)
	return PLUGIN_HANDLED
}

/* ----------------------- */

public BypassGuard_RequestProxyStatus(pPlayer, const szIP[], iMaxTries) {
	if(!g_eCvar[CVAR__USE_FOR_PROXY]) {
		return PLUGIN_CONTINUE
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	// NOTE: 'bg_check_ip' command depends on this cache (instant return), see main plugin
	if(TrieGetArray(g_tCheckCache, szIP, eCheckCache, sizeof(eCheckCache))) {
		BypassGuard_SendProxyStatus(pPlayer, eCheckCache[CHECK_CACHE__IS_PROXY], .bSuccess = true)
		return PLUGIN_HANDLED
	}

	func_MakeRequest(pPlayer, szIP, iMaxTries, CHECK_TYPE__PROXY)
	return PLUGIN_HANDLED
}

/* ----------------------- */

public BypassGuard_RequestGeoData(pPlayer, const szIP[], iMaxTries) {
	if(!g_eCvar[CVAR__USE_FOR_GEO]) {
		return PLUGIN_CONTINUE
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	// NOTE: 'bg_check_ip' command depends on this cache (instant return), see main plugin
	if(TrieGetArray(g_tCheckCache, szIP, eCheckCache, sizeof(eCheckCache))) {
		BypassGuard_SendGeoData( pPlayer, eCheckCache[CHECK_CACHE__COUNTRY_CODE],
			eCheckCache[CHECK_CACHE__COUNTRY_NAME], .bSuccess = true );

		return PLUGIN_HANDLED
	}

	if(pPlayer) {
		g_bitDataQueue[pPlayer] |= DATA_QUEUE__GEO
	}

	func_MakeRequest(pPlayer, szIP, iMaxTries, CHECK_TYPE__GEO)
	return PLUGIN_HANDLED
}

/* ----------------------- */

func_MakeRequest(pPlayer, const szIP[], iMaxTries, iCheckType) {
	new iCurrentKey = g_eCvar[CVAR__CURRENT_KEY]

	new eExtData[CHECK_EXT_DATA_STRUCT]

	eExtData[CHECK_EXT_DATA__TYPE] = iCheckType
	eExtData[CHECK_EXT_DATA__PLAYER_USERID] = get_user_userid(pPlayer) // return 0 if out of range
	copy(eExtData[CHECK_EXT_DATA__IP], MAX_IP_LENGTH - 1, szIP)
	eExtData[CHECK_EXT_DATA__KEY_NUMBER] = iCurrentKey
	eExtData[CHECK_CACHE__MAX_TRIES] = clamp(iMaxTries, 1, 5)

	new iDataID = iphub_send_request(szIP, g_szApiKey[iCurrentKey], .attempts = eExtData[CHECK_CACHE__MAX_TRIES])

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))
}

/* -------------------- */

public iphub_response_received(request, response[IPHubData], status) {
	if(g_bPluginEnded || !iphub_initiated_by_me(request)) {
		return PLUGIN_CONTINUE
	}

	new eExtData[CHECK_EXT_DATA_STRUCT]

	if(!TrieGetArray(g_tCheckExtData, fmt("%i", request), eExtData, sizeof(eExtData))) {
		BypassGuard_LogError( fmt("[Error] Can't find data for check with id %i", request) )
		return PLUGIN_HANDLED
	}

	TrieDeleteKey(g_tCheckExtData, fmt("%i", request))

	new pPlayer = find_player("k", eExtData[CHECK_EXT_DATA__PLAYER_USERID])

	if(status != REQUEST_SUCCESSFUL) {
		/* {
			"code":"TooManyRequests",
			"message":"You've exceeded your rate limit of 1000 request(s) per 86400 second(s)."
		} */
		if(
			status == KEY_EXPIRED
				&&
			eExtData[CHECK_EXT_DATA__KEY_NUMBER] == g_eCvar[CVAR__CURRENT_KEY]
				&&
			func_TrySwitchToNextKey()
		) {
			if(func_TryRetry(pPlayer, eExtData)) {
				return PLUGIN_HANDLED
			}
		}

		BypassGuard_LogError( fmt("HTTP status: %i", status) )

		if(response[iphub_error][0]) {
			BypassGuard_LogError( fmt("Error: %s", response[iphub_error]) )
		}

		return PLUGIN_HANDLED
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	formatex(eCheckCache[CHECK_CACHE__AS], MAX_AS_LEN - 1, "AS%i", response[iphub_asn])

	copy(eCheckCache[CHECK_CACHE__DESC], MAX_DESC_LEN - 1, response[iphub_isp])

	if(response[iphub_block] == 1 || (g_eCvar[CVAR__BAN_SUSPICIOUS] && response[iphub_block] == 2)) {
		eCheckCache[CHECK_CACHE__IS_PROXY] = true
	}

	if(response[iphub_code][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_CODE], IHC_COUNTRY_CODE_LEN - 1, response[iphub_code])
	}
	else {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_CODE], IHC_COUNTRY_CODE_LEN - 1, _NA_)
	}

	if(response[iphub_name][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_NAME], IHC_COUNTRY_NAME_LEN - 1, response[iphub_name])
	}
	else {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_NAME], IHC_COUNTRY_NAME_LEN - 1, _NA_)
	}

	TrieSetArray(g_tCheckCache, eExtData[CHECK_EXT_DATA__IP], eCheckCache, sizeof(eCheckCache))

	if(!pPlayer) {
		return PLUGIN_HANDLED
	}

	switch(eExtData[CHECK_EXT_DATA__TYPE]) {
		case CHECK_TYPE__AS: {
			g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__AS

			BypassGuard_SendAsInfo( pPlayer, eCheckCache[CHECK_CACHE__AS],
				eCheckCache[CHECK_CACHE__DESC], .bSuccess = true );
		}
		case CHECK_TYPE__PROXY: {
			BypassGuard_SendProxyStatus(pPlayer, eCheckCache[CHECK_CACHE__IS_PROXY], .bSuccess = true)
		}
		case CHECK_TYPE__GEO: {
			g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__GEO

			BypassGuard_SendGeoData( pPlayer, eCheckCache[CHECK_CACHE__COUNTRY_CODE],
				eCheckCache[CHECK_CACHE__COUNTRY_NAME], .bSuccess = true );

			if(g_bitDataQueue[pPlayer] & DATA_QUEUE__AS) {
				g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__AS

				BypassGuard_SendAsInfo( pPlayer, eCheckCache[CHECK_CACHE__AS],
					eCheckCache[CHECK_CACHE__DESC], .bSuccess = true );
			}
		}
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

bool:func_TryRetry(pPlayer, eExtData[CHECK_EXT_DATA_STRUCT]) {
	static const szCheckType[CHECK_TYPE_ENUM][] = {
		"AS number",
		"proxy status",
		"country info"
	}

	if(!pPlayer || eExtData[CHECK_EXT_DATA__RETRY]) {
		BypassGuard_LogError( fmt( "[Error] Can't get %s for IP '%s'",
			szCheckType[ eExtData[CHECK_EXT_DATA__TYPE] ], eExtData[CHECK_EXT_DATA__IP] ) );

		if(pPlayer) {
			switch(eExtData[CHECK_EXT_DATA__TYPE]) {
				case CHECK_TYPE__AS: {
					g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__AS

					BypassGuard_SendAsInfo(pPlayer, .szAsNumber = "", .szDesc = "", .bSuccess = false)
				}
				case CHECK_TYPE__PROXY: {
					BypassGuard_SendProxyStatus(pPlayer, .IsProxy = false, .bSuccess = false)
				}
				case CHECK_TYPE__GEO: {
					g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__GEO

					BypassGuard_SendGeoData(pPlayer, _NA_, _NA_, .bSuccess = false)

					if(g_bitDataQueue[pPlayer] & DATA_QUEUE__AS) {
						g_bitDataQueue[pPlayer] &= ~DATA_QUEUE__AS

						BypassGuard_SendAsInfo(pPlayer, .szAsNumber = "", .szDesc = "", .bSuccess = false)
					}
				}
			}
		}

		return false
	}

	// else ->

	new iCurrentKey = g_eCvar[CVAR__CURRENT_KEY]

	eExtData[CHECK_EXT_DATA__KEY_NUMBER] = iCurrentKey
	eExtData[CHECK_EXT_DATA__RETRY] = true

	new iDataID = iphub_send_request( eExtData[CHECK_EXT_DATA__IP], g_szApiKey[iCurrentKey],
		.attempts = eExtData[CHECK_CACHE__MAX_TRIES] );

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))

	return true
}

/* ----------------------- */

bool:func_TrySwitchToNextKey() {
	if(g_iLoadedKeys > 1) {
		new iCurrentKey = g_eCvar[CVAR__CURRENT_KEY]
		new iNewKey

		if(iCurrentKey < g_iLoadedKeys - 1) {
			iNewKey = iCurrentKey + 1
			func_SetCurrentKey(iNewKey)
		}
		else {
			func_SetCurrentKey(0)
		}

		BypassGuard_LogError( fmt( "[Notice] Request limit for API key '%i', switching to API key '%i' of '%i'",
			iCurrentKey + 1, iNewKey + 1, g_iLoadedKeys ) );

		return true
	}

	BypassGuard_LogError( fmt("[Error] Request limit reached, and no more available API keys!") )
	return false
}

/* ----------------------- */

func_LoadApiKeys() {
	new szFolderName[32]
	BypassGuard_GetPluginFolderName(szFolderName, chx(szFolderName))

	new szPath[PLATFORM_MAX_PATH]
	new iLen = get_localinfo("amxx_configsdir", szPath, chx(szPath))
	formatex(szPath[iLen], chx_len(szPath), "/%s/%s", szFolderName, KEY_FILE_NAME)

	new hFile = fopen(szPath, "r")

	if(!hFile) {
		if(file_exists(szPath)) {
			BypassGuard_LogError( fmt("[Error] Can't open existing '%s'", KEY_FILE_NAME) )
			return
		}

		hFile = fopen(szPath, "w")

		if(!hFile) {
			BypassGuard_LogError( fmt("[Error] Can't create default '%s'", KEY_FILE_NAME) )
			return
		}

		fputs( hFile,
			"; Ключи к API iphub'а. Зарегистрируйтесь на https://iphub.info/ , получите бесплатный ключ (1000 проверок/сутки), и введите его сюда^n\
			; При необходимости вы можете указать несколько ключей (по 1 ключу на строку)^n\
			; API-keys for iphub. Register at https://iphub.info/ , get free key (1000 checks/day), and set it here^n\
			; You can set multiple keys if you need to (1 key per row)^n\
			;"
		);

		fclose(hFile)
		return
	}

	new szBuffer[MAX_API_KEY_LEN + 8]

	while(!feof(hFile)) {
		if(g_iLoadedKeys == MAX_KEYS) {
			BypassGuard_LogError( fmt("[Error] Keys limit reached! Increase 'MAX_KEYS' in .sma !") )
			break
		}

		fgets(hFile, szBuffer, chx(szBuffer))
		trim(szBuffer)

		if(szBuffer[0] == ';' || !szBuffer[0]) {
			continue
		}

		copy(g_szApiKey[g_iLoadedKeys++], MAX_API_KEY_LEN - 1, szBuffer)
	}

	fclose(hFile)

	if(!g_iLoadedKeys) {
		BypassGuard_LogError( fmt("[Error] No API keys loaded, you need to fill '%s'", KEY_FILE_NAME) )
		set_fail_state("No API keys loaded, you need to fill '%s'", KEY_FILE_NAME)
	}
}

/* ----------------------- */

public client_disconnected(pPlayer) {
	g_bitDataQueue[pPlayer] = 0
}

/* ----------------------- */

public plugin_end() {
	g_bPluginEnded = true

	if(g_tCheckExtData) {
		TrieDestroy(g_tCheckExtData)
		TrieDestroy(g_tCheckCache)
	}
}