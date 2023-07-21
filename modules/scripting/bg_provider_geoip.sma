/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин предоставляет название и код страны.

	Используемый модуль: geoip
	Свежая база (amxmodx/data): http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz

	Использование:
		1) Обновите базу
		2) Перезапустите сервер (выключите и снова включите)
		3) Запустите плагин
*/

/* История обновлений:
	0.1 (17.09.2019):
		* Открытый релиз
	0.2 (17.09.2019 fix):
		* Исправление логики при работе с API
	0.3 (30.05.2023):
		* Актуализация API
*/

new const PLUGIN_VERSION[] = "0.3"

/* ----------------------- */

#include <amxmodx>
#include <geoip>
#include <bypass_guard>

#define chx charsmax

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: GeoIP", PLUGIN_VERSION, "mx?!")
}

/* ----------------------- */

public BypassGuard_RequestGeoData(pPlayer, const szIP[], iMaxTries) {
	new szCode[MAX_CODE_LEN * 2], szCountry[MAX_COUNTRY_LEN]
	func_GetCountryCode(szIP, szCode, chx(szCode))
	func_GetCountryName(szIP, szCountry, chx(szCountry))

	BypassGuard_SendGeoData(pPlayer, szCode, szCountry, true)

	return PLUGIN_HANDLED
}

/* -------------------- */

func_GetCountryCode(const szIP[], szBuffer[], iMaxLen) {
	new szCode[MAX_CODE_LEN]

	if(geoip_code2_ex(szIP, szCode)) {
		copy(szBuffer, iMaxLen, szCode)
		return
	}

	copy(szBuffer, iMaxLen, _NA_)
}

/* -------------------- */

func_GetCountryName(const szIP[], szBuffer[], iMaxLen) {
	if(!geoip_country_ex(szIP, szBuffer, iMaxLen)) {
		copy(szBuffer, iMaxLen, _NA_)
	}
}