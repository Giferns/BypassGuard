/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин может как предоставлять AS-номер, так и проверять IP-адрес на proxy/VPN (регулируется кварами).

	Используемый сервис: https://iphub.info/ (требуется регистрация; вход через прокси, если не открывается)
	Описание API: https://iphub.info/api

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
	0.3 (27.09.2019):
		* Исправление логики получения AS-номеров (вайтлист/блеклист AS не работал)
	0.4 (26.10.2019):
		* Улучшение логики работы с несколькими ключами
	0.5 (28.12.2019):
		* Улучшение логики работы с несколькими ключами (thx Rey)
*/

new const PLUGIN_VERSION[] = "0.5"

/* ----------------------- */

#define AUTO_CFG // Создавать конфиг с кварами в 'configs/plugins', и запускать его ?

const MAX_KEYS = 5 // Макс. кол-во API-ключей. Увеличить при необходимости.

new const KEY_FILE_NAME[] = "iphub_api_keys.ini"

/* ----------------------- */

#include <amxmodx>
#include <grip>
#include <bypass_guard>

#define chx charsmax
#define chx_len(%0) charsmax(%0) - iLen

#define MAX_API_KEY_LEN 64

enum _:CHECK_TYPE_ENUM {
	CHECK_TYPE__AS,
	CHECK_TYPE__PROXY
}

enum _:CHECK_EXT_DATA_STRUCT {
	CHECK_EXT_DATA__TYPE,
	CHECK_EXT_DATA__CHECK_TRIES,
	CHECK_EXT_DATA__PLAYER_USERID,
	CHECK_EXT_DATA__IP[MAX_IP_LENGTH],
	CHECK_EXT_DATA__KEY_NUMBER
}

enum _:CHECK_CACHE_DATA_STRUCT {
	CHECK_CACHE__AS[MAX_AS_LEN],
	CHECK_CACHE__DESC[MAX_DESC_LEN],
	bool:CHECK_CACHE__IS_PROXY
}

enum _:CVAR_ENUM {
	CVAR__USE_FOR_AS,
	CVAR__USE_FOR_PROXY,
	CVAR__BAN_SUSPICIOUS,
	CVAR__CURRENT_KEY
}

new g_eCvar[CVAR_ENUM]
new bool:g_bPluginEnded
new Trie:g_tCheckExtData
new Trie:g_tCheckCache
new g_szApiKey[MAX_KEYS][MAX_API_KEY_LEN]
new g_iLoadedKeys
new g_pCvarCurrKey

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: iphub.info", PLUGIN_VERSION, "mx?!")

	g_tCheckExtData = TrieCreate()
	g_tCheckCache = TrieCreate()

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

	bind_pcvar_num( create_cvar("bg_iphub_ban_suspicious", "0",
		.description = "Count suspicious IPs as proxy (can bring false detections)?^n\
		Has no effect if 'bg_iphub_use_for_proxy' is set to 0"),
		g_eCvar[CVAR__BAN_SUSPICIOUS]
	);

#if defined AUTO_CFG
	AutoExecConfig()
#endif

	/* --- */

	g_pCvarCurrKey = get_cvar_pointer("_bg_iphub_current_key")

	if(g_pCvarCurrKey) {
		bind_pcvar_num(g_pCvarCurrKey, g_eCvar[CVAR__CURRENT_KEY])
	}

	/* --- */

	func_LoadApiKeys()
}

/* ----------------------- */

public OnConfigsExecuted() {
	if(g_pCvarCurrKey) {
		return
	}

	g_pCvarCurrKey = create_cvar("_bg_iphub_current_key", "0", .description = "Utility, don't touch!")
	bind_pcvar_num(g_pCvarCurrKey, g_eCvar[CVAR__CURRENT_KEY])
}

/* ----------------------- */

public BypassGuard_RequestAsInfo(pPlayer, szIP[], iMaxTries) {
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

	func_MakeRequest(pPlayer, szIP, iMaxTries, CHECK_TYPE__AS)
	return PLUGIN_HANDLED
}

/* ----------------------- */

public BypassGuard_RequestProxyStatus(pPlayer, szIP[], iMaxTries) {
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

func_MakeRequest(pPlayer, szIP[], iMaxTries, iCheckType) {
	new iDataID = func_GetCheckID()

	new eExtData[CHECK_EXT_DATA_STRUCT]

	new iCurrentKey = func_GetCurrentKey()

	eExtData[CHECK_EXT_DATA__TYPE] = iCheckType
	eExtData[CHECK_EXT_DATA__CHECK_TRIES] = iMaxTries
	eExtData[CHECK_EXT_DATA__PLAYER_USERID] = get_user_userid(pPlayer) // return 0 if out of range
	copy(eExtData[CHECK_EXT_DATA__IP], MAX_IP_LENGTH - 1, szIP)
	eExtData[CHECK_EXT_DATA__KEY_NUMBER] = iCurrentKey

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))

	new GripRequestOptions:hRequestOptions = grip_create_default_options(.timeout = -1.0)

	grip_options_add_header(hRequestOptions, "X-Key", g_szApiKey[iCurrentKey])

	grip_request( fmt("http://v2.api.iphub.info/ip/%s", szIP),
		Empty_GripBody, GripRequestTypeGet, "OnCheckComplete", hRequestOptions, iDataID );

	grip_destroy_options(hRequestOptions)
}

/* ----------------------- */

func_GetCheckID() {
	new iDataID

	do {
		iDataID = random_num(0, 10000)
	}
	while(TrieKeyExists(g_tCheckExtData, fmt("%i", iDataID)))

	return iDataID
}

/* -------------------- */

public OnCheckComplete(iDataID) {
	if(g_bPluginEnded) {
		return
	}

	new eExtData[CHECK_EXT_DATA_STRUCT]

	if(!TrieGetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))) {
		BypassGuard_LogError( fmt("[Error] Can't find data for check with id %i", iDataID) )
		return
	}

	TrieDeleteKey(g_tCheckExtData, fmt("%i", iDataID))

	new pPlayer = find_player("k", eExtData[CHECK_EXT_DATA__PLAYER_USERID])

	func_AgregateCheckResponse(pPlayer, iDataID, eExtData)
}

/* -------------------- */

func_AgregateCheckResponse(pPlayer, iDataID, eExtData[CHECK_EXT_DATA_STRUCT]) {
	new szBuffer[MAX_RESPONSE_LEN]

	new GripResponseState:iResponseState = grip_get_response_state()

	if(iResponseState != GripResponseStateSuccessful) {
		if(func_TryRetry(pPlayer, eExtData, iDataID)) {
			return
		}

		BypassGuard_LogError( fmt("Response state: %i", iResponseState) )

		if(iResponseState == GripResponseStateError && grip_get_error_description(szBuffer, chx(szBuffer))) {
			BypassGuard_LogError( fmt("%s", szBuffer) )
		}

		return
	}

	new GripHTTPStatus:iHttpStatus = grip_get_response_status_code()

	if(iHttpStatus != GripHTTPStatusOk) {
		/* {
			"code":"TooManyRequests",
			"message":"You've exceeded your rate limit of 1000 request(s) per 86400 second(s)."
		} */
		if(
			iHttpStatus == GripHTTPStatusTooManyRequests
				&&
			eExtData[CHECK_EXT_DATA__KEY_NUMBER] == g_eCvar[CVAR__CURRENT_KEY]
		) {
			func_TrySwitchToNextKey()
		}

		if(func_TryRetry(pPlayer, eExtData, iDataID)) {
			return
		}

		BypassGuard_LogError( fmt("HTTP status: %i", iHttpStatus) )

		if(grip_get_response_body_string(szBuffer, chx(szBuffer))) {
			BypassGuard_LogError( fmt("Response body: %s", szBuffer) )
		}

		return
	}

	new GripJSONValue:hResponceBody = grip_json_parse_response_body(szBuffer, chx(szBuffer))

	if(hResponceBody == Invalid_GripJSONValue) {
		if(func_TryRetry(pPlayer, eExtData, iDataID)) {
			return
		}

		if(szBuffer[0]) {
			BypassGuard_LogError( fmt("Error text: %s", szBuffer) )
		}

		if(grip_get_response_body_string(szBuffer, chx(szBuffer))) {
			BypassGuard_LogError( fmt("Response body: %s", szBuffer) )
		}

		return
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	new GripJSONValue:hAsNumber = grip_json_object_get_value(hResponceBody, "asn")
	new iAsNumber = grip_json_get_number(hAsNumber)
	grip_destroy_json_value(hAsNumber)
	formatex(eCheckCache[CHECK_CACHE__AS], MAX_AS_LEN - 1, "AS%i", iAsNumber)

	new GripJSONValue:hIsp = grip_json_object_get_value(hResponceBody, "isp")
	grip_json_get_string(hIsp, eCheckCache[CHECK_CACHE__DESC], MAX_DESC_LEN - 1)
	grip_destroy_json_value(hIsp)

	new GripJSONValue:hProxy = grip_json_object_get_value(hResponceBody, "block")
	new iProxy = grip_json_get_number(hProxy)
	grip_destroy_json_value(hProxy)

	if(iProxy == 1 || (g_eCvar[CVAR__BAN_SUSPICIOUS] && iProxy == 2)) {
		eCheckCache[CHECK_CACHE__IS_PROXY] = true
	}

	TrieSetArray(g_tCheckCache, eExtData[CHECK_EXT_DATA__IP], eCheckCache, sizeof(eCheckCache))

	grip_destroy_json_value(hResponceBody)

	if(pPlayer) {
		if(eExtData[CHECK_EXT_DATA__TYPE] == CHECK_TYPE__AS) {
			BypassGuard_SendAsInfo( pPlayer, eCheckCache[CHECK_CACHE__AS],
				eCheckCache[CHECK_CACHE__DESC], .bSuccess = true );
		}
		else { // CHECK_TYPE__PROXY
			BypassGuard_SendProxyStatus(pPlayer, eCheckCache[CHECK_CACHE__IS_PROXY], .bSuccess = true)
		}
	}
}

/* -------------------- */

bool:func_TryRetry(pPlayer, eExtData[CHECK_EXT_DATA_STRUCT], iDataID) {
	static const szCheckType[CHECK_TYPE_ENUM][] = {
		"AS number",
		"proxy status"
	}

	if(!pPlayer || --eExtData[CHECK_EXT_DATA__CHECK_TRIES] == 0) {
		BypassGuard_LogError( fmt( "[Error] Can't get %s for IP '%s'",
			szCheckType[ eExtData[CHECK_EXT_DATA__TYPE] ], eExtData[CHECK_EXT_DATA__IP] ) );

		if(pPlayer) {
			if(eExtData[CHECK_EXT_DATA__TYPE] == CHECK_TYPE__AS) {
				BypassGuard_SendAsInfo(pPlayer, .szAsNumber = "", .szDesc = "", .bSuccess = false)
			}
			else { // CHECK_TYPE__PROXY
				BypassGuard_SendProxyStatus(pPlayer, .IsProxy = false, .bSuccess = false)
			}
		}

		return false

	}

	// else ->

	new iCurrentKey = func_GetCurrentKey()

	eExtData[CHECK_EXT_DATA__KEY_NUMBER] = iCurrentKey

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))

	new GripRequestOptions:hRequestOptions = grip_create_default_options(.timeout = -1.0)

	grip_options_add_header(hRequestOptions, "X-Key", g_szApiKey[iCurrentKey])

	grip_request( fmt("http://v2.api.iphub.info/ip/%s", eExtData[CHECK_EXT_DATA__IP]),
		Empty_GripBody, GripRequestTypeGet, "OnCheckComplete", hRequestOptions, iDataID );

	grip_destroy_options(hRequestOptions)

	return true
}

/* ----------------------- */

func_GetCurrentKey() {
	if(!g_pCvarCurrKey) {
		return 0
	}

	if(g_eCvar[CVAR__CURRENT_KEY] >= g_iLoadedKeys) {
		set_pcvar_num(g_pCvarCurrKey, 0)
		return 0
	}

	return g_eCvar[CVAR__CURRENT_KEY]
}

/* ----------------------- */

func_TrySwitchToNextKey() {
	if(g_pCvarCurrKey && g_iLoadedKeys > 1) {
		new iCurrentKey = g_eCvar[CVAR__CURRENT_KEY]
		new iNewKey

		if(iCurrentKey < g_iLoadedKeys - 1) {
			iNewKey = iCurrentKey + 1
			set_pcvar_num(g_pCvarCurrKey, iNewKey)
		}
		else {
			set_pcvar_num(g_pCvarCurrKey, 0)
		}

		BypassGuard_LogError( fmt( "[Error] Request limit for API key '%i', switching to API key '%i' of '%i'",
			iCurrentKey + 1, iNewKey + 1, g_iLoadedKeys ) );
	}
	else {
		BypassGuard_LogError( fmt("[Error] Request limit reached, and no more available API keys!") )
	}
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
			; You can set multiple keys if you need to (1 key per row)"
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
}

/* ----------------------- */

public plugin_end() {
	g_bPluginEnded = true

	if(g_tCheckExtData) {
		TrieDestroy(g_tCheckExtData)
		TrieDestroy(g_tCheckCache)
	}
}