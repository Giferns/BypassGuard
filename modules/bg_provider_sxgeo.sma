/*
	Данный плагин является модулем-провайдером информации для основного плагина (ядра), - Bypass Guard.
	Данный плагин предоставляет название и код страны.

	Используемый модуль: SxGeo https://dev-cs.ru/resources/469/
	Свежая база (amxmodx/data): https://sypexgeo.net/files/SxGeoCity_utf8.zip

	Использование:
		1) Установите модуль SxGeo
		2) Установите/обновите базу
		3) Перезапустите сервер (выключите и снова включите)
		4) Запустите плагин
*/

/* История обновлений:
	1.0 (19.02.2020):
		* Первый релиз
*/

new const PLUGIN_VERSION[] = "1.0"

/* ----------------------- */

#include <amxmodx>
#include <sxgeo>
#include <bypass_guard>

#define chx charsmax

new const _NA_[] = "N/A"

/* ----------------------- */

public plugin_init() {
	register_plugin("[BG] Provider: SxGeo", PLUGIN_VERSION, "mx?!")
}

/* ----------------------- */

public BypassGuard_RequestGeoData(pPlayer, szIP[], iMaxTries) {
	new szCode[MAX_CODE_LEN * 2], szCountry[MAX_COUNTRY_LEN]
	func_GetCountryCode(szIP, szCode, chx(szCode))
	func_GetCountryName(szIP, szCountry, chx(szCountry))

	BypassGuard_SendGeoData(pPlayer, szCode, szCountry, true)

	return PLUGIN_HANDLED
}

/* -------------------- */

func_GetCountryCode(szIP[], szBuffer[], iMaxLen) {
	new szCode[MAX_CODE_LEN]

	if(sxgeo_region_code(szIP, szCode, chx(szCode))) {
		copy(szBuffer, iMaxLen, szCode)
		return
	}

	copy(szBuffer, iMaxLen, _NA_)
}

/* -------------------- */

func_GetCountryName(szIP[], szBuffer[], iMaxLen) {
	if(!sxgeo_country(szIP, szBuffer, iMaxLen)) {
		copy(szBuffer, iMaxLen, _NA_)
	}
}