/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин может как предоставлять AS-номер, так и проверять IP-адрес на proxy/VPN (регулируется кварами).

	Используемый сервис: http://ip-api.com/ (регистрация не требуется)
	Описание API: http://ip-api.com/docs/api:json

	Плюсы:
		* Не нужна регистрация

	Минусы:
		* Средний уровень точности проверки на proxy/VPN

	Использование:
		1) Запустите плагин
		2) Отредактируйте квары плагина в конфиге в 'configs/plugins'
		3) Смените карту, чтобы новые значения кваров вступили в силу
*/

/* История обновлений:
	0.1 (20.09.2019):
		* Открытый релиз
	0.2 (30.05.2023):
		* Актуализация API
		* Добавлен квар 'bg_ipapi_use_for_geo'
		* Добавлен квар 'bg_ipapi_hosting_as_proxy'
	0.3 (16.07.2023):
		* Бамп версии под совместимость с новой версией ядра
*/

new const PLUGIN_VERSION[] = "0.3"

/* ----------------------- */

// Create config with cvars in 'configs/plugins' and execute it?
//
// Создавать конфиг с кварами в 'configs/plugins', и запускать его ?
#define AUTO_CFG

/* ----------------------- */

#include <amxmodx>
#include <grip>
#include <bypass_guard>

#define chx charsmax

enum _:CHECK_TYPE_ENUM {
	CHECK_TYPE__AS,
	CHECK_TYPE__PROXY,
	CHECK_TYPE__GEO
}

enum _:CHECK_EXT_DATA_STRUCT {
	CHECK_EXT_DATA__TYPE,
	CHECK_EXT_DATA__CHECK_TRIES,
	CHECK_EXT_DATA__PLAYER_USERID,
	CHECK_EXT_DATA__IP[MAX_IP_LENGTH]
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
	CVAR__HOSTING_AS_PROXY
}

new g_eCvar[CVAR_ENUM]
new bool:g_bPluginEnded
new Trie:g_tCheckExtData
new Trie:g_tCheckCache

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: ip-api.com", PLUGIN_VERSION, "mx?!")

	g_tCheckExtData = TrieCreate()
	g_tCheckCache = TrieCreate()

	bind_pcvar_num( create_cvar("bg_ipapi_use_for_as", "1",
		.description = "Use this provider for getting AS number?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_AS]
	);

	bind_pcvar_num( create_cvar("bg_ipapi_use_for_proxy", "1",
		.description = "Use this provider for proxy status checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_PROXY]
	);

	bind_pcvar_num( create_cvar("bg_ipapi_use_for_geo", "1",
		.description = "Use this provider for country checking?^n\
		Set this cvar to 0 if you use another plugin for that purpose"),
		g_eCvar[CVAR__USE_FOR_GEO]
	);

	bind_pcvar_num( create_cvar("bg_ipapi_hosting_as_proxy", "1",
		.description = "Consider hosting providers as proxy providers?"),
		g_eCvar[CVAR__HOSTING_AS_PROXY]
	);

#if defined AUTO_CFG
	AutoExecConfig()
#endif
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

	func_MakeRequest(pPlayer, szIP, iMaxTries, CHECK_TYPE__GEO)
	return PLUGIN_HANDLED
}

/* ----------------------- */

func_MakeRequest(pPlayer, const szIP[], iMaxTries, iCheckType) {
	new iDataID = func_GetCheckID()

	new eExtData[CHECK_EXT_DATA_STRUCT]

	eExtData[CHECK_EXT_DATA__TYPE] = iCheckType
	eExtData[CHECK_EXT_DATA__CHECK_TRIES] = iMaxTries
	eExtData[CHECK_EXT_DATA__PLAYER_USERID] = get_user_userid(pPlayer) // return 0 if out of range
	copy(eExtData[CHECK_EXT_DATA__IP], MAX_IP_LENGTH - 1, szIP)

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))

	grip_request( fmt("http://ip-api.com/json/%s?fields=16960003", szIP),
		Empty_GripBody, GripRequestTypeGet, "OnCheckComplete", .userData = iDataID );
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

	new GripJSONValue:hStatus = grip_json_object_get_value(hResponceBody, "status")
	grip_json_get_string(hStatus, szBuffer, chx(szBuffer))
	grip_destroy_json_value(hStatus)

	if(equal(szBuffer, "fail")) {
		if(func_TryRetry(pPlayer, eExtData, iDataID)) {
			grip_destroy_json_value(hResponceBody)
			return
		}

		new GripJSONValue:hMessage = grip_json_object_get_value(hResponceBody, "message")
		grip_json_get_string(hMessage, szBuffer, chx(szBuffer))
		grip_destroy_json_value(hMessage)
		grip_destroy_json_value(hResponceBody)

		BypassGuard_LogError( fmt("Fail message: %s", szBuffer) )

		return
	}

	new eCheckCache[CHECK_CACHE_DATA_STRUCT]

	new GripJSONValue:hAsNumber = grip_json_object_get_value(hResponceBody, "as")
	grip_json_get_string(hAsNumber, szBuffer, chx(szBuffer))
	grip_destroy_json_value(hAsNumber)
	parse(szBuffer, eCheckCache[CHECK_CACHE__AS], MAX_AS_LEN - 1)

	new GripJSONValue:hIsp = grip_json_object_get_value(hResponceBody, "isp")
	grip_json_get_string(hIsp, eCheckCache[CHECK_CACHE__DESC], MAX_DESC_LEN - 1)
	grip_destroy_json_value(hIsp)

	new GripJSONValue:hProxy = grip_json_object_get_value(hResponceBody, "proxy")
	eCheckCache[CHECK_CACHE__IS_PROXY] = grip_json_get_bool(hProxy)
	grip_destroy_json_value(hProxy)

	if(!eCheckCache[CHECK_CACHE__IS_PROXY] && g_eCvar[CVAR__HOSTING_AS_PROXY]) {
		new GripJSONValue:hHosting = grip_json_object_get_value(hResponceBody, "hosting")
		eCheckCache[CHECK_CACHE__IS_PROXY] = grip_json_get_bool(hHosting)
		grip_destroy_json_value(hHosting)
	}

	new GripJSONValue:hCountry = grip_json_object_get_value(hResponceBody, "country")
	grip_json_get_string(hCountry, eCheckCache[CHECK_CACHE__COUNTRY_NAME], chx(eCheckCache[CHECK_CACHE__COUNTRY_NAME]))
	grip_destroy_json_value(hCountry)
	if(!eCheckCache[CHECK_CACHE__COUNTRY_NAME][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_NAME], chx(eCheckCache[CHECK_CACHE__COUNTRY_NAME]), _NA_)
	}

	new GripJSONValue:hCode = grip_json_object_get_value(hResponceBody, "countryCode")
	grip_json_get_string(hCode, eCheckCache[CHECK_CACHE__COUNTRY_CODE], chx(eCheckCache[CHECK_CACHE__COUNTRY_CODE]))
	grip_destroy_json_value(hCode)
	if(!eCheckCache[CHECK_CACHE__COUNTRY_CODE][0]) {
		copy(eCheckCache[CHECK_CACHE__COUNTRY_CODE], chx(eCheckCache[CHECK_CACHE__COUNTRY_CODE]), _NA_)
	}

	TrieSetArray(g_tCheckCache, eExtData[CHECK_EXT_DATA__IP], eCheckCache, sizeof(eCheckCache))

	grip_destroy_json_value(hResponceBody)

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

bool:func_TryRetry(pPlayer, eExtData[CHECK_EXT_DATA_STRUCT], iDataID) {
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

		return false

	}

	// else ->

	TrieSetArray(g_tCheckExtData, fmt("%i", iDataID), eExtData, sizeof(eExtData))

	grip_request( fmt("http://ip-api.com/json/%s?fields=16960003", eExtData[CHECK_EXT_DATA__IP]),
		Empty_GripBody, GripRequestTypeGet, "OnCheckComplete", .userData = iDataID );

	return true
}

/* ----------------------- */

public plugin_end() {
	g_bPluginEnded = true

	if(g_tCheckExtData) {
		TrieDestroy(g_tCheckExtData)
		TrieDestroy(g_tCheckCache)
	}
}