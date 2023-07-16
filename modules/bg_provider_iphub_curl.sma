/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин может как предоставлять AS-номер, так и проверять IP-адрес на proxy/VPN (регулируется кварами).

	Используемый сервис: https://iphub.info/ (требуется регистрация; вход через прокси, если не открывается)
	Описание API: https://iphub.info/api

	Требования:
		* Amxx Curl:
			* https://dev-cs.ru/resources/651/
			* https://github.com/Polarhigh/AmxxCurl/releases

	Плюсы:
		* Высокий уровень точности проверки на proxy/VPN
		* Возможность задать несколько ключей

	Минусы:
		* Необходима регистрация
		* Зачастую невнятное описание провайдера при получении AS-номера

	Использование:
		1) Зарегистрируйтесь на сервисе и получите бесплатный ключ (используйте прокси, если сайт не открывается)
		2) Пропишите ключ (на новой строке) в конфиг 'iphub_api_keys.ini'
		3) Запустите плагин
		4) Отредактируйте квары плагина в конфиге в 'configs/plugins'
		5) Смените карту, чтобы новые значения кваров вступили в силу
*/

/* История обновлений:
	0.1 (17.09.2019):
		* Открытый релиз
	0.2 (20.09.2019):
		* Исправление логики переключения между несколькими API-ключами
	0.3-curl (27.09.2019):
		* Исправление логики получения AS-номеров (вайтлист/блеклист AS не работал)
		* CURL-версия для тех, кто имеет проблемы с модулем 'gRIP'
	0.3.1-curl (29.09.2019):
		* Исправление логики обработки ошибок
	0.4-curl (26.10.2019):
		* Улучшение логики работы с несколькими ключами
	0.5-curl (28.12.2019):
		* Улучшение логики работы с несколькими ключами (thx Rey)
	0.6-curl (30.05.2023):
		* Уход от логики с кваром-указателем # ключа и OnConfigsExecuted() в сторону localinfo
		* Актуализация API
		* Незначительные улучшения
		* Добавлен квар 'bg_iphub_use_for_geo'
*/

new const PLUGIN_VERSION[] = "0.6-curl"

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

new const DIR_NAME[] = "bypass_guard" // 'data/%s'

/* ----------------------- */

#include <amxmodx>
#include <curl>
#include <json>
#include <bypass_guard>

// default is 4096
#pragma dynamic 8192

#define chx charsmax
#define chx_len(%0) charsmax(%0) - iLen

#define MAX_API_KEY_LEN 64
#define CURL_BUFFER_SIZE 512

enum _:CHECK_TYPE_ENUM {
	CHECK_TYPE__AS,
	CHECK_TYPE__PROXY,
	CHECK_TYPE__GEO
}

enum _:CHECK_EXT_DATA_STRUCT {
	CHECK_EXT_DATA__TYPE,
	CHECK_EXT_DATA__CHECK_TRIES,
	CHECK_EXT_DATA__PLAYER_USERID,
	CHECK_EXT_DATA__IP[MAX_IP_LENGTH],
	CHECK_EXT_DATA__KEY_NUMBER,
	CHECK_EXT_DATA__FILE_HANDLE,
	CHECK_EXT_DATA__SLIST_HANDLE,
	CHECK_EXT_DATA__DATA_ID
}

enum _:EXPECTED_JSON_KEY_COUNT {
	JSON_KEY__IP,
	JSON_KEY__COUNTRY_CODE,
	JSON_KEY__COUNTRY_NAME,
	JSON_KEY__AS,
	JSON_KEY__PROVIDER,
	JSON_KEY__CHECK_STATE,
	JSON_KEY__HOSTNAME
}

// sizes as in iphubclient.inc (bg_provider_iphubclient.sma), see iphub_code and iphub_name
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

new g_eCvar[CVAR_ENUM]
new bool:g_bPluginEnded
new Trie:g_tCheckCache
new g_szApiKey[MAX_KEYS][MAX_API_KEY_LEN]
new g_iLoadedKeys
new g_szDataDir[PLATFORM_MAX_PATH]

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: iphub.info", PLUGIN_VERSION, "mx?!")

	/* --- */

	g_tCheckCache = TrieCreate()

	/* --- */

	bind_pcvar_num( create_cvar("bg_iphub_use_for_as", "1",
		.description = "Use this provider for getting AS number?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_AS]
	);

	bind_pcvar_num( create_cvar("bg_iphub_use_for_proxy", "1",
		.description = "Use this provider for proxy status checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_PROXY]
	);

	bind_pcvar_num( create_cvar("bg_iphub_use_for_geo", "1",
		.description = "Use this provider for country checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_GEO]
	);

	bind_pcvar_num( create_cvar("bg_iphub_ban_suspicious", "0",
		.description = "Count suspicious IPs as proxy (can bring false detections)?^n\
		Has no effect if 'bg_iphub_use_for_proxy' is set to 0"),
		g_eCvar[CVAR__BAN_SUSPICIOUS]
	);

#if defined AUTO_CFG
	AutoExecConfig()
#endif

	/* --- */

	get_localinfo("amxx_datadir", g_szDataDir, chx(g_szDataDir))
	format(g_szDataDir, chx(g_szDataDir), "%s/%s", g_szDataDir, DIR_NAME)

	if(!dir_exists(g_szDataDir)) {
		mkdir(g_szDataDir)
	}

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

	func_MakeRequestStep1(pPlayer, szIP, iMaxTries, CHECK_TYPE__AS)
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

	func_MakeRequestStep1(pPlayer, szIP, iMaxTries, CHECK_TYPE__PROXY)
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

	func_MakeRequestStep1(pPlayer, szIP, iMaxTries, CHECK_TYPE__GEO)
	return PLUGIN_HANDLED
}

/* ----------------------- */

func_MakeRequestStep1(pPlayer, const szIP[], iMaxTries, iCheckType) {
	new eExtData[CHECK_EXT_DATA_STRUCT]

	eExtData[CHECK_EXT_DATA__DATA_ID] = random_num(0, 10000)

	eExtData[CHECK_EXT_DATA__TYPE] = iCheckType
	eExtData[CHECK_EXT_DATA__CHECK_TRIES] = iMaxTries
	eExtData[CHECK_EXT_DATA__PLAYER_USERID] = get_user_userid(pPlayer) // return 0 if out of range
	copy(eExtData[CHECK_EXT_DATA__IP], MAX_IP_LENGTH - 1, szIP)

	func_MakeRequestStep2(eExtData)
}

/* -------------------- */

func_MakeRequestStep2(eExtData[CHECK_EXT_DATA_STRUCT]) {
	new szFile[PLATFORM_MAX_PATH]

	formatex( szFile, chx(szFile), "%s/%s_%i", g_szDataDir, eExtData[CHECK_EXT_DATA__IP],
		eExtData[CHECK_EXT_DATA__DATA_ID] );

	eExtData[CHECK_EXT_DATA__FILE_HANDLE] = fopen(szFile, "wb")

	if(!eExtData[CHECK_EXT_DATA__FILE_HANDLE]) {
		BypassGuard_LogError( fmt("[Error] Can't open '%s' for writing!", szFile) )
		return
	}

	new iCurrentKey = g_eCvar[CVAR__CURRENT_KEY]

	eExtData[CHECK_EXT_DATA__KEY_NUMBER] = iCurrentKey

	new CURL:hCurl = curl_easy_init()

	curl_easy_setopt(hCurl, CURLOPT_BUFFERSIZE, CURL_BUFFER_SIZE)
	curl_easy_setopt(hCurl, CURLOPT_URL, fmt("http://v2.api.iphub.info/ip/%s", eExtData[CHECK_EXT_DATA__IP]))

	new curl_slist:hList
	hList = curl_slist_append(hList, fmt("X-Key: %s", g_szApiKey[iCurrentKey]))
	curl_easy_setopt(hCurl, CURLOPT_HTTPHEADER, hList)

	curl_easy_setopt(hCurl, CURLOPT_WRITEDATA, eExtData[CHECK_EXT_DATA__FILE_HANDLE])
	curl_easy_setopt(hCurl, CURLOPT_WRITEFUNCTION, "OnWrite")

	eExtData[CHECK_EXT_DATA__SLIST_HANDLE] = hList

	curl_easy_perform(hCurl, "OnDownloadComplete", eExtData, sizeof(eExtData))
}

/* -------------------- */

public OnDownloadComplete(CURL:hCurl, CURLcode:iCode, eExtData[CHECK_EXT_DATA_STRUCT]) {
	if(g_bPluginEnded) {
		return
	}

	new szFile[PLATFORM_MAX_PATH]

	formatex( szFile, chx(szFile), "%s/%s_%i", g_szDataDir, eExtData[CHECK_EXT_DATA__IP],
		eExtData[CHECK_EXT_DATA__DATA_ID] );

	fclose(eExtData[CHECK_EXT_DATA__FILE_HANDLE])
	curl_slist_free_all(curl_slist:eExtData[CHECK_EXT_DATA__SLIST_HANDLE])

	curl_easy_cleanup(hCurl)

	new pPlayer = find_player("k", eExtData[CHECK_EXT_DATA__PLAYER_USERID])

	if(iCode != CURLE_OK) {
		if(!func_TryRetry(pPlayer, eExtData, szFile)) {
			new szError[256]
			curl_easy_strerror(iCode, szError, chx(szError))
			BypassGuard_LogError( fmt("[Error] Curl error code #%i, IP '%s'", iCode, eExtData[CHECK_EXT_DATA__IP]) )
			BypassGuard_LogError( fmt("[Error] Curl error: %s", szError) )
		}

		return
	}

	/* --- */

	if(!file_exists(szFile)) {
		if(!func_TryRetry(pPlayer, eExtData, szFile)) {
			BypassGuard_LogError( fmt("[Error] File '%s' not found!", szFile) )
		}

		return
	}

	new JSON:hJson = json_parse(szFile, true, true)

	if(hJson == Invalid_JSON) {
		if(func_TryRetry(pPlayer, eExtData, szFile)) {
			return
		}

		new bool:bError, szBuffer[256], hFile = fopen(szFile, "r")

		if(!hFile) {
			BypassGuard_LogError( fmt("[Error] Can't open wrong file '%s' for analysis", szFile) )
		}
		else {
			while(!feof(hFile)) {
				fgets(hFile, szBuffer, chx(szBuffer))

				/*  <html>
					<head><title>502 Bad Gateway</title></head>
					<body>
					<center><h1>502 Bad Gateway</h1></center>
					<hr><center>nginx/1.15.8</center>
					</body>
					</html> */
				if(contain(szBuffer, "502") != -1) {
					bError = true
					break
				}
			}

			fclose(hFile)

			if(bError) {
				BypassGuard_LogError("[Error] HTTP responce code 502 (Bad Gateway)")
			}
			else {
				BypassGuard_LogError( fmt("[Error] Something is wrong with file '%s'", szFile) )
			}
		}

		return
	}

	new iCount = json_object_get_count(hJson)

	if(iCount < EXPECTED_JSON_KEY_COUNT) {
		json_free(hJson)

		new iError, szBuffer[256], hFile = fopen(szFile, "r")

		if(!hFile) {
			if(func_TryRetry(pPlayer, eExtData, szFile)) {
				return
			}

			BypassGuard_LogError( fmt("[Error] Can't open wrong file '%s' for analysis", szFile) )
		}
		else {
			while(!feof(hFile)) {
				fgets(hFile, szBuffer, chx(szBuffer))

				/* {
					"code":"TooManyRequests",
					"message":"You've exceeded your rate limit of 1000 request(s) per 86400 second(s)."
				} */
				if(contain(szBuffer, "exceeded") != -1) {
					iError = 1
					break
				}

				// {"code":"Forbidden","message":"Invalid API key"}
				// {"code":"Forbidden","message":"Missing X-Key header"}
				if(contain(szBuffer, "Invalid API") != -1 || contain(szBuffer, "Missing X-Key") != -1) {
					iError = 2
					break
				}
			}

			fclose(hFile)

			switch(iError) {
				case 0: {
					if(!func_TryRetry(pPlayer, eExtData, szFile)) {
						BypassGuard_LogError( fmt("[Error] Wrong key count (%i/%i) in file '%s'",
							iCount, EXPECTED_JSON_KEY_COUNT, szFile) );
					}
				}
				case 1: {
					if(eExtData[CHECK_EXT_DATA__KEY_NUMBER] == g_eCvar[CVAR__CURRENT_KEY]) {
						func_TrySwitchToNextKey()
					}

					func_TryRetry(pPlayer, eExtData, szFile)
				}
				case 2: {
					if(!func_TryRetry(pPlayer, eExtData, szFile)) {
						BypassGuard_LogError("[Error] Invalid API Key!")
					}
				}
			}
		}

		return
	}

	delete_file(szFile)

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	new JSON:hAsNumber = json_object_get_value(hJson, "asn", false)
	new iAsNumber = json_get_number(hAsNumber)
	json_free(hAsNumber)
	formatex(eCheckCache[CHECK_CACHE__AS], MAX_AS_LEN - 1, "AS%i", iAsNumber)

	new JSON:hIsp = json_object_get_value(hJson, "isp", false)
	json_get_string(hIsp, eCheckCache[CHECK_CACHE__DESC], MAX_DESC_LEN - 1)
	json_free(hIsp)

	new JSON:hProxy = json_object_get_value(hJson, "block", false)
	new iProxy = json_get_number(hProxy)
	json_free(hProxy)

	new JSON:hCountryName = json_object_get_value(hJson, "countryName", false)
	json_get_string(hCountryName, eCheckCache[CHECK_CACHE__COUNTRY_NAME], chx(eCheckCache[CHECK_CACHE__COUNTRY_NAME]))
	json_free(hCountryName)
	if(!eCheckCache[CHECK_CACHE__COUNTRY_NAME][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_NAME], chx(eCheckCache[CHECK_CACHE__COUNTRY_NAME]), _NA_)
	}

	new JSON:hCountryCode = json_object_get_value(hJson, "countryCode", false)
	json_get_string(hCountryCode, eCheckCache[CHECK_CACHE__COUNTRY_CODE], chx(eCheckCache[CHECK_CACHE__COUNTRY_CODE]))
	json_free(hCountryCode)
	if(!eCheckCache[CHECK_CACHE__COUNTRY_CODE][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_CODE], chx(eCheckCache[CHECK_CACHE__COUNTRY_CODE]), _NA_)
	}

	json_free(hJson)

	if(iProxy == 1 || (g_eCvar[CVAR__BAN_SUSPICIOUS] && iProxy == 2)) {
		eCheckCache[CHECK_CACHE__IS_PROXY] = true
	}

	TrieSetArray(g_tCheckCache, eExtData[CHECK_EXT_DATA__IP], eCheckCache, sizeof(eCheckCache))

	if(!pPlayer) {
		return
	}

	switch(eExtData[CHECK_EXT_DATA__TYPE]) {
		case CHECK_TYPE__AS: {
			BypassGuard_SendAsInfo( pPlayer, eCheckCache[CHECK_CACHE__AS],
				eCheckCache[CHECK_CACHE__DESC], .bSuccess = true );
		}
		case CHECK_TYPE__PROXY: {
			BypassGuard_SendProxyStatus(pPlayer, eCheckCache[CHECK_CACHE__IS_PROXY], .bSuccess = true)
		}
		case CHECK_TYPE__GEO: {
			BypassGuard_SendGeoData( pPlayer, eCheckCache[CHECK_CACHE__COUNTRY_CODE],
				eCheckCache[CHECK_CACHE__COUNTRY_NAME], .bSuccess = true );
		}
	}
}

/* -------------------- */

public OnWrite(szData[], iSize, nmemb, hFile) {
	new iActualSize = iSize * nmemb

	fwrite_blocks(hFile, szData, iActualSize, BLOCK_CHAR)

	return iActualSize
}

/* -------------------- */

bool:func_TryRetry(pPlayer, eExtData[CHECK_EXT_DATA_STRUCT], szFile[]) {
	static const szCheckType[CHECK_TYPE_ENUM][] = {
		"AS number",
		"proxy status",
		"country info"
	}

	if(!pPlayer || --eExtData[CHECK_EXT_DATA__CHECK_TRIES] == 0) {
		BypassGuard_LogError( fmt( "[Error] Can't get %s for IP '%s'",
			szCheckType[ eExtData[CHECK_EXT_DATA__TYPE] ], eExtData[CHECK_EXT_DATA__IP] ) );

		if(pPlayer) {
			switch(eExtData[CHECK_EXT_DATA__TYPE]) {
				case CHECK_TYPE__AS: {
					BypassGuard_SendAsInfo(pPlayer, .szAsNumber = "", .szDesc = "", .bSuccess = false)
				}
				case CHECK_TYPE__PROXY: {
					BypassGuard_SendProxyStatus(pPlayer, .IsProxy = false, .bSuccess = false)
				}
				case CHECK_TYPE__GEO: {
					BypassGuard_SendGeoData(pPlayer, _NA_, _NA_, .bSuccess = false)
				}
			}
		}

		new szNewFileName[PLATFORM_MAX_PATH]
		formatex(szNewFileName, chx(szNewFileName), "%s_error", szFile)
		rename_file(szFile, szNewFileName, .relative = 1)

		return false
	}

	// else ->

	func_MakeRequestStep2(eExtData)

	return true
}

/* ----------------------- */

func_TrySwitchToNextKey() {
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

		return
	}

	BypassGuard_LogError( fmt("[Error] Request limit reached, and no more available API keys!") )
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

public plugin_end() {
	g_bPluginEnded = true

	if(g_tCheckCache) {
		TrieDestroy(g_tCheckCache)
	}
}