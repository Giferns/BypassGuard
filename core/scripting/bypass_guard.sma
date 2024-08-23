/*
	Плагин: Bypass Guard

	Основное назначение: Противодействие обходу банов по SteamID/IP

	Офф. топик: https://dev-cs.ru/resources/649/

	Использующийся инструментарий:
		* Агрегация номера автономной системы (AS-номера провайдера), к которой принадлежит IP
		* Агрегация кода страны (GeoIP-модуль)
		* Агрегация статуса IP-адреса в онлайн-сервисе проверок на Proxy/VPN
		* Чёрный и белый списки IP-адресов

	Данный плагин частично основан на функционале двух других плагинов:
		* Proxy/VPN check 1.1b от juice: https://dev-cs.ru/resources/475/
		* SubnetBan 2.2 от Lev: https://dev-cs.ru/resources/162/

	Требования:
		* Amx Mod X 1.9.0, либо новее: https://dev-cs.ru/resources/405/
		* Reapi [опционально]: https://dev-cs.ru/resources/73/

	Установка и настройка: смотрите офф. топик, раздел 'установка и настройка'

	Доступные команды:
		* bg_allow_steamid <steamid> - Выдаёт указанному steamid иммунитет ко всем проверкам

		Внимание! Внесение AS/IP в чёрный список не проверяет сервер на наличие игроков, подпадающих под
			добавленное ограничение. Другими словами, забанив AS/IP игрока, который в данный момент находится
			на сервере, вам необходимо кикнуть его самостоятельно.

		* bg_as_blacklist_add <as number> "<comment>"[optional]
		* bg_as_blacklist_del <as number>
		* bg_as_blacklist_show <page>

		* bg_as_whitelist_add <as number> "<comment>"[optional]
		* bg_as_whitelist_del <as number>
		* bg_as_whitelist_show <page>

		* bg_ip_blacklist_add <start ip> <end ip> "<comment>"[optional]
		* bg_ip_blacklist_del <start ip> <end ip>
		* bg_ip_blacklist_show <page>

		* bg_ip_whitelist_add <start ip> <end ip> "<comment>"[optional]
		* bg_ip_whitelist_del <start ip> <end ip>
		* bg_ip_whitelist_show <page>

		* bg_find_ip <ip> - Позволяет проверить наличие указанного IP в диапазонах чёрного и белого списков

		* bg_find_as <as number> - Позволяет проверить наличие указанного AS-номера в чёрном и белом списках

		* bg_get_as_by_ip <ip> - Позволяет получить AS-номер для указанного IP

		* bg_check_ip <ip> - Позволяет проверить IP-адрес на причастность к Proxy/VPN

		* bg_flush_data <1-3>:
			1 - Обнулить хранилище, содержащее steamid'ы, имеющие иммунитет ко всем проверкам (nvault)
			2 - Обнулить чёрный и белый список IP, удалить файл-список диапазонов IP
			3 - Обнулить чёрный и белый список AS-номеров, удалить файл-список AS-номеров

		* bg_status - Выводит информацию о присутствующих игроках
*/

/* Thx to:
	fantom за пример работы с форматом JSON
	juice за плагин 'Proxy/VPN check'
	Lev за плагин 'SubnetBan' и модуль 'Whois'
	Polarhigh за модуль 'Amxx Curl'
	Inline за модуль 'gRIP'
	voed за пример работы с модулем 'gRIP'
	Garey, AleXr, wopox1337 за версию 'gRIP' под Windows: https://dev-cs.ru/threads/2789/post-65613
	SKAJIbnEJIb за конструктивную критику и идеи
*/

/* История обновлений:
	08.01.2019:
		* Закрытый релиз
	09.01.2019:
		* Добавлен белый список AS
		* Доработки функционала консольных команд
		* Улучшена информативность лог-файла
		* Фиксы обнаруженных ошибок
	19.01.2019:
		* Смена сервиса проверки на Proxy/VPN с 'mind-media.com' на 'iphub.info'
		* Смена метода работы с WEB (HTTP:X -> Amxx Curl)
		* Теперь использование команд (добавление/удаление) логируется в файл
		* Логирование разделёно на несколько частей, см. 'LOG_ENUM'
		* Добавлены квары, предоставляющие некоторую гибкость поведения
		* Команда 'bg_get_as_by_ip' теперь так же показывает поле 'Description' (провайдер)
		* Добавлена команда 'bg_status'
	22.01.2019:
		* Улучшено поведение при возникновении ошибок при проверке на Proxy/VPN
		* Для команды 'bg_allow_steamid' добавлен учёт 'VALVE_'
		* Список разрешённых стран переведён на загрузку из файла
		* Загрузка API-ключей переведена на загрузку из файла
		* Информация, выводящаяся игроку при кике, выведена в lang-файл
		* Добавлен квар 'bypass_guard_show_url'
		* Добавлен квар 'bypass_guard_check_delay'
		* Добавлен квар 'bypass_guard_kick_delay'
	24.01.2019:
		* Убран код, пропускающий казахов без проверки на Proxy/VPN (проблема была актуальна для mind-media.com)
		* Устранение ряда незначительных недосмотров
		* Все команды: srvcmd -> concmd, логирование использования сопровождается информацией о пользователе
		* Открытый релиз
	24.02.2019:
		* Добавлен учёт отсутствия квара 'amx_default_access', спасибо w0w
		* Пофикшен баг с пустым выводом команды 'bg_status', спасибо Nordic Warrior
		* Хранение статуса IP-адресов переведено на SQL (не забудьте прописать sqlite или mysql в 'configs/modules.ini'). Спасибо fantom.
		* Добавлены квары 'bg_sql_'. Рекомендуется удалить конфиг в 'configs/plugins', дабы он пересоздался.
		* Добавлен квар 'bg_divide_logs_by_month'
		* Для команды 'bg_get_as_by_ip' добавлен вывод страны
		* Добавлена команда 'bg_check_ip', позволяющая проверить IP-адрес на причастность к Proxy/VPN
		* Улучшена информативность поля "тип доступа" для команды 'bg_status', логов 'ALLOW.log', 'DENY.log', и 'PROXY_CHECK.log'
		* Исправление выявленных недочётов в логике работы проверок
		* Отдельная благодарность за подсказки: fl0wer, Sonyx, bionext
	24.05.2019:
		* Прекращена поддержка AMXX 183, теперь плагин требует AMXX 190+
		* Потенциальное исправление падений сервера для тех, у кого они наблюдаются
		* Исправление невозможности ввода нестандартного SteamID (STEAM_/VALVE_ + 2 цифры до ':') для команды 'bg_allow_steamid'
		* Добавлен квар 'bypass_guard_immunity_flags'. Игроки, имеющие любой из перечисленных в его значении флагов, пропускаются
			на сервер без каких-либо проверок (аналогично иммунитету по SteamID). Внимание! При использовании данного
			квара (т.е. когда его значение не "") проверка наличия иммунитета через квар 'amx_default_access' отключается!
		* Исправление ряда незначительных ошибок
	07.06.2019:
		* Добавлен учёт кода возврата "неправильный ключ". Ранее учитывалось только отсутствие ключа.
	14.09.2019:
		* Переработка плагина на работу с сервисом ip-api.com (теперь не нужно регистрироваться и получать ключ)
		* Переход на модуль gRIP (отказ от модулей whois, curl, json)
		* Упразднение работы с долгим кешем (СУБД)
		* Добавлен квар 'bypass_guard_country_check_mode' с тремя режимами работы:
			0 - не проверять страну
			1 - проверять по белому списку
			2 - проверять по чёрному списку
		* Плагин стал проще и быстрее (упразднено более тысячи строк)
		* Обратите внимание, изменилось имя исходного файла (bypass_guard_iphub.sma -> bypass_guard.sma)
		* Изменилась схема работы плагина, проверка на proxy/vpn теперь выполняется до проверки страны
		* Пересмотрен функционал доступных команд
	17.09.2019:
		* Реализована модульность, - API для подключения сторонних провайдеров данных. Смотрите раздел
			'установка и настройка' в офф. топике.
	21.09.2019:
		* Добавлен сток is_user_steam(), использование Reapi теперь является опциональным
		* Изменение логики проверки игрока (некритичное)
		* Релиз разделён на ядро и модули (из архива удалено всё, что прямо не связано с ядром)
	1.0.0 (27.09.2019):
		* Переход на семантическое версионирование, базовая версия плагина - 1.0.0
		* Добавлен квар 'bypass_guard_check_port' (спасибо SISA за идею), необходимо обновить конфиг
		* Модернизирован квар 'bypass_guard_kick_if_cant_check', необходимо обновить конфиг
		* Теперь логирование IP-адреса включает в себя порт клиента
		* Добавлен учёт асинхронного ответа в логике работы с провайдером кода и названия страны
		* Для команды 'bg_as_blacklist_add' добавлен аргумент 'check_port'
		* Исправление периодического отсутствия дополнительной информации в консоли кикнутого игрока
		* Реализована возможность добавления неизвестной страны (N/A) в список разрешённых/запрещённых стран
		* В лог-файл теперь так же выводятся флаги, присвоенные кварами 'bypass_guard_check_port' и
			'bypass_guard_kick_if_cant_check'
	1.0.1 (28.09.2019):
		* Исправление логики проверки страны (вайтлист/блеклист страны не работал), спасибо stalin_alex
		* Стандартное значение квара 'bypass_guard_check_port' изменено на "a", т.к. по результатам теста,
			достаточно много сервисов позволяют совершать обходы со стандартного порта. За тесты спасибо MrDojo.
			Рекомендуется установить указанное значение для данного квара.
	1.0.2 (29.05.2023):
		* Удалён квар 'bypass_guard_check_port' и связанный с ним функционал
	1.0.3 (29.05.2023):
		* Косметические улучшения
	1.0.4 (29.05.2023):
		* Реализовано автоматическое удаление повреждённого nvault
	1.0.5 (29.05.2023):
		* Исправлен баг с использованием команды 'bg_check_ip' из-под клиента игры (отсутствие ответа). Спасибо NordicWarrior
	1.0.6 (30.05.2023):
		* Расширение API (внимание, требуется так же обновить все плагины-провайдеры данных!)
	1.0.7 (16.07.2023):
		* Улучшение логики порядка проверок (запрос геоданных теперь последовательный, а не параллельный)
		* Квару 'bypass_guard_country_check_mode' добавлен режим -1 (запрашивать данные, но пропускать проверку страны)
	1.0.8 (16.07.2023):
		* Расширение API под совместимость с предстоящим плагином Supervisor
	1.0.9 (10.02.2024):
		* Добавлено принудительное конвертирование кода страны в верхний регистр в нативе BypassGuard_RequestGeoData(),
			так как iphub.info начал периодически отдавать код страны в нижнем регистре, что ломает логику проверки
		* Добавлен квар 'bypass_guard_check_proxy', позволяющий отключить проверку на Proxy/VPN. Добавлен для серверов из
			России, т.к. украинские игроки иногда не могут зайти на сервера в РФ напрямую, и используют для этого Proxy/VPN.
			Не рекомендуется отключать проверку на Proxy/VPN просто так, это сильно ослабляет защиту от обхода бана!
	1.0.10 (23.08.2024):
		* Добавлена возможность проверять игрока на Proxy/VPN только в том случае, если Supervisor имеет активную блокировку,
				и у проверяемого игрока нет whitepass (т.е. игрок опознан сервером как 'новый') (идея SKAJIbnEJIb).
			* Для квара bypass_guard_check_proxy добавлен режим "2"
			* Нативу BypassGuard_SendSupervisingResult добавлены аргументы bByWhitepass и bStrictStatus
			* Изменён порядок логики, теперь запрос к супервайзеру отправляется раньше проверки на Proxy/VPN
		* Добавлена возможность пропускать проверку игроков, которые, по данным статистики, провели на
			сервере # или более минут (идея SKAJIbnEJIb).
			* Добавлен квар bypass_guard_allow_by_stats
			* Добавлен квар bypass_guard_stats_type
			* bypass_guard.inc: в энумерацию ALLOW_TYPE_ENUM добавлен элемент ALLOW_TYPE__STATS_IMMUNITY
*/

new const PLUGIN_VERSION[] = "1.0.10"

/* ----------------------- */

// Create config with cvars in 'configs/plugins' and execute it?
//
// Создавать конфиг с кварами в 'configs/plugins', и запускать его ?
#define AUTO_CFG

// Default access flag for all console commands
//
// Флаг доступа по-умолчанию ко всем консольным командам
#define ACCESS_FLAG ADMIN_CFG

new DIR_NAME[] = "bypass_guard" // 'configs/%s', 'data/%s', 'logs/%s'
new const IP_FILE_NAME[] = "ip_list.ini"
new const AS_FILE_NAME[] = "as_list.ini"
new const ALLOWED_COUNTRY_FILE_NAME[] = "allowed_countries.ini"
new const BANNED_COUNTRY_FILE_NAME[] = "banned_countries.ini"
new const IMMUNE_STEAMS_VAULT[] = "bypass_guard_steams"

enum _:LOG_ENUM { // Don't touch this!
	LOG__CMD,
	//
	// <--- new log type goes here!
	//
	LOG__ERROR, // Must be the last before LOG__DENY
	// Must be the last in the enum --->
	LOG__DENY,
	LOG__ALLOW
	// <---
}

new const LOG_NAME[LOG_ENUM][] = {
	"CMD.log",
	"ERROR.log",
	"DENY.log",
	"ALLOW.log"
}

/* ----------------------- */

#include <amxmodx>
#include <nvault>
#tryinclude <reapi>
#include <bypass_guard>

// default is 4096
//#pragma dynamic 8192

#define chx charsmax

#define CheckBit(%0,%1) (%0 & (1 << %1))
#define SetBit(%0,%1) (%0 |= (1 << %1))
#define ClearBit(%0,%1) (%0 &= ~(1 << %1))

#define MAX_COMMENT_LEN 48

/* --- */

enum {
	STATE__NOT_SET, // dummy
	STATE__WHITELIST,
	STATE__BAN
}

enum _:LIST_TYPE_ENUM {
	LIST_TYPE__BLACKLIST,
	LIST_TYPE__WHITELIST
}

new const LIST_NAME[LIST_TYPE_ENUM][] = {
	"blacklist",
	"whitelist"
}

enum _:RANGE_DATA_STRUCT {
	RDS__START_IP,
	RDS__END_IP,
	RDS__COMMENT[MAX_COMMENT_LEN]
}

enum _:AS_DATA_STRUCT {
	ASD__NUMBER[MAX_AS_LEN],
	ASD__COMMENT[MAX_COMMENT_LEN]
}

enum _:AS_TRIE_STRUCT {
	AST__STATE,
	AST__ARRAY_POS
}

enum _:PCVAR_ENUM {
	PCVAR__IMMUNITY_FLAGS,
	PCVAR__AMX_DEFAULT_ACCESS,
	PCVAR__KICK_IF_CANT_CHECK
}

enum _:CVAR_ENUM {
	CVAR__PLUGIN_ENABLED,
	CVAR__MAX_CHECK_TRIES,
	CVAR__ALLOW_STEAM,
	CVAR__SHOW_URL,
	Float:CVAR_F__CHECK_DELAY,
	Float:CVAR_F__KICK_DELAY,
	CVAR__COUNTRY_CHECK_MODE,
	CVAR__CHECK_PROXY,
	CVAR__ALLOW_BY_STATS,
	CVAR__STATS_TYPE
}

new g_pCvar[PCVAR_ENUM]
new g_eCvar[CVAR_ENUM]
new g_iIpCount[LIST_TYPE_ENUM]
new g_hImmunity = INVALID_HANDLE
new g_szIpListFile[PLATFORM_MAX_PATH]
new g_szAsListFile[PLATFORM_MAX_PATH]
new g_iAsCount[LIST_TYPE_ENUM]
new g_bitDefAccFlags
new g_bitImmunityFlags
new bool:g_bPluginEnded
new g_eLogFile[LOG_ENUM][PLATFORM_MAX_PATH]
new any:g_iAccessType[MAX_PLAYERS + 1] = { INVALID_ACCESS_TYPE, ... }
new g_szAccess[MAX_PLAYERS + 1][MAX_ACCESS_LEN]
new g_szAccessExt[MAX_PLAYERS + 1][MAX_ACCESS_EXT_LEN]
new g_szAsNumber[MAX_PLAYERS + 1][MAX_AS_LEN]
new g_szDesc[MAX_PLAYERS + 1][MAX_DESC_LEN]
new g_szCode[MAX_PLAYERS + 1][MAX_CODE_LEN * 2]
new g_szCountry[MAX_PLAYERS + 1][MAX_COUNTRY_LEN]
new Array:g_eIpArray[LIST_TYPE_ENUM]
new Array:g_aAsArray[LIST_TYPE_ENUM]
new Trie:g_tAsNumbers
new Trie:g_tAllowedCodes
new Trie:g_tBannedCodes
new g_szIP[MAX_PLAYERS + 1][MAX_IP_LENGTH]
new g_szAddress[MAX_PLAYERS + 1][MAX_IP_WITH_PORT_LENGTH]
new g_szAuthID[MAX_PLAYERS + 1][MAX_AUTHID_LENGTH]
new g_fwdRequestAsInfo
new g_fwdRequestProxyStatus
new g_fwdRequestGeoData
new g_fwdPlayerCheckComplete
new g_fwdRequestSupervising
new bool:g_bGotInfo
new g_pRequestAdmin
new g_szCmdIP[MAX_IP_LENGTH]
new g_bitPlayerFailFlags[MAX_PLAYERS + 1]
new g_bitSkipGeo
new g_bitKickFailCheckFlags
new bool:g_bCheckComplete[MAX_PLAYERS + 1]
new g_ePlayerData[BG_PLAYER_DATA_STRUCT]
new g_szSvStatus[MAX_PLAYERS + 1][MAX_SV_STATUS_LEN]
new bool:g_bSvAllowConnect[MAX_PLAYERS + 1]

/* -------------------- */

public plugin_init() {
	register_plugin("Bypass Guard", PLUGIN_VERSION, "mx?!")
	register_dictionary("bypass_guard.txt")

	RegCvars()
}

/* -------------------- */

RegCvars() {
	bind_pcvar_num( create_cvar("bypass_guard_enabled", "1",
		.description = "Enable/Disable plugin work"), g_eCvar[CVAR__PLUGIN_ENABLED] );

	/* --- */

	new pCvar = create_cvar( "bypass_guard_kick_if_cant_check", "0",
		.description = "Kick player if check fails (must be set like ^"abc^")?^n\
		0 - Don't kick^n\
		Kick if:^n\
		a - AS check fails^n\
		b - Proxy/VPN check fails^n\
		c - Country check fails" );

	new szFlags[32]; get_pcvar_string(pCvar, szFlags, chx(szFlags))
	g_bitKickFailCheckFlags = read_flags(szFlags)
	g_pCvar[PCVAR__KICK_IF_CANT_CHECK] = pCvar
	hook_cvar_change(pCvar, "hook_CvarChange")

	/* --- */

	bind_pcvar_num( create_cvar("bypass_guard_allow_steam", "1",
		.description = "Allow steam players to join without checks?"), g_eCvar[CVAR__ALLOW_STEAM] );

	bind_pcvar_num( create_cvar("bypass_guard_country_check_mode", "1",
		.has_min = true, .min_val = -1.0,
		.has_max = true, .max_val = 2.0,
		.description = "Defines country check mode:^n\
		-1 - Request geodata but skip country check^n\
		0 - Don't check country (country provider will not be used at all)^n\
		1 - Whitelist^n\
		2 - Blacklist"),
		g_eCvar[CVAR__COUNTRY_CHECK_MODE] );

	/* --- */

	bind_pcvar_num( create_cvar("bypass_guard_check_proxy", "1",
		.description = "Enable (1) or disable (0) Proxy/VPN check mode:^n\
		0 - Disable^n\
		1 - Enable^n\
		2 - Enable, if Supervisor addon have an active ASN block and player don't have a whitepass"),
		g_eCvar[CVAR__CHECK_PROXY]
	);

	/* --- */

	bind_pcvar_num( create_cvar("bypass_guard_allow_by_stats", "0",
		.description = "Players, that played # or more minutes, can join without checks (0 - disable feature)"),
		g_eCvar[CVAR__ALLOW_BY_STATS]
	);

	/* --- */

	bind_pcvar_num( create_cvar("bypass_guard_stats_type", "0",
		.description = "Stats type for cvar 'bypass_guard_allow_by_stats':^n\
			0 - CSstatsX SQL (freeman)^n\
			1 - CsStats MySQL (fungun)^n\
			2 - CMSStats MySQL (zhorzh78)^n\
			3 - Simple Online Logger"),
		g_eCvar[CVAR__STATS_TYPE]
	);

	/* --- */

	pCvar = create_cvar( "bypass_guard_immunity_flags", "d",
		.description = "Allow players with any of specified flags to join without checks^n\
		If value is empty, standart immunity by absence of 'amx_default_access' flag will be used" );

	get_pcvar_string(pCvar, szFlags, chx(szFlags))
	g_bitImmunityFlags = read_flags(szFlags)
	g_pCvar[PCVAR__IMMUNITY_FLAGS] = pCvar
	hook_cvar_change(pCvar, "hook_CvarChange")

	/* --- */

	bind_pcvar_num( create_cvar("bypass_guard_show_url", "1",
		.description = "Show URL when player gets kicked (don't forget to edit 'data/lang/bypass_guard.txt') ?"), g_eCvar[CVAR__SHOW_URL] );

	bind_pcvar_num( create_cvar("bypass_guard_max_check_tries", "2", .has_min = true, .min_val = 1.0,
		.description = "Max check tries"), g_eCvar[CVAR__MAX_CHECK_TRIES] );

	bind_pcvar_float( create_cvar("bypass_guard_check_delay", "0.1", .has_min = true, .min_val = 0.1,
		.description = "Player check delay"), g_eCvar[CVAR_F__CHECK_DELAY] );

	bind_pcvar_float( create_cvar("bypass_guard_kick_delay", "1.0", .has_min = true, .min_val = 0.1,
		.description = "Player kick delay (low values may break URL showing!)"), g_eCvar[CVAR_F__KICK_DELAY] );

	/* --- */

#if defined AUTO_CFG
	AutoExecConfig()
#endif
}

/* -------------------- */

public plugin_cfg() {
	g_hImmunity = nvault_open(IMMUNE_STEAMS_VAULT)

	if(g_hImmunity == INVALID_HANDLE) {
		log_to_file(g_eLogFile[LOG__ERROR], "[Error] Nvault '%s' is corrupted? Try to create new nvault...", IMMUNE_STEAMS_VAULT)

		new szPath[PLATFORM_MAX_PATH]
		new iLen = get_localinfo("amxx_datadir", szPath, chx(szPath))
		formatex(szPath[iLen], chx(szPath) - iLen, "/vault/%s.vault", IMMUNE_STEAMS_VAULT)
		delete_file(szPath)
		formatex(szPath[iLen], chx(szPath) - iLen, "/vault/%s.journal", IMMUNE_STEAMS_VAULT)
		delete_file(szPath)

		g_hImmunity = nvault_open(IMMUNE_STEAMS_VAULT)

		if(g_hImmunity == INVALID_HANDLE) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Error creating new nVault!", IMMUNE_STEAMS_VAULT)
			set_fail_state("[Immunity] Error creating new nVault!")
		}
	}

	g_eIpArray[LIST_TYPE__BLACKLIST] = ArrayCreate(RANGE_DATA_STRUCT, 1)
	g_eIpArray[LIST_TYPE__WHITELIST] = ArrayCreate(RANGE_DATA_STRUCT, 1)
	g_aAsArray[LIST_TYPE__BLACKLIST] = ArrayCreate(AS_DATA_STRUCT, 1)
	g_aAsArray[LIST_TYPE__WHITELIST] = ArrayCreate(AS_DATA_STRUCT, 1)
	g_tAsNumbers = TrieCreate()
	g_tAllowedCodes = TrieCreate()
	g_tBannedCodes = TrieCreate()

	/* --- */

	g_fwdRequestAsInfo = CreateMultiForward("BypassGuard_RequestAsInfo", ET_STOP, FP_CELL, FP_STRING, FP_CELL)

	g_fwdRequestProxyStatus = CreateMultiForward( "BypassGuard_RequestProxyStatus",
		ET_STOP, FP_CELL, FP_STRING, FP_CELL );

	g_fwdRequestGeoData = CreateMultiForward("BypassGuard_RequestGeoData", ET_STOP, FP_CELL, FP_STRING, FP_CELL)

	g_fwdRequestSupervising = CreateMultiForward("BypassGuard_RequestSupervising", ET_STOP, FP_CELL, FP_STRING)

	g_fwdPlayerCheckComplete = CreateMultiForward("BypassGuard_PlayerCheckComplete", ET_IGNORE, FP_CELL, FP_CELL, FP_ARRAY)

	/* --- */

	register_concmd("bg_allow_steamid", "concmd_AllowSteamID", ACCESS_FLAG)
	register_concmd("bg_as_blacklist_add", "concmd_AddToAsList", ACCESS_FLAG)
	register_concmd("bg_as_blacklist_del", "concmd_DelFromAsList", ACCESS_FLAG)
	register_concmd("bg_as_blacklist_show", "concmd_ShowAsList", ACCESS_FLAG)
	register_concmd("bg_as_whitelist_add", "concmd_AddToAsList", ACCESS_FLAG)
	register_concmd("bg_as_whitelist_del", "concmd_DelFromAsList", ACCESS_FLAG)
	register_concmd("bg_as_whitelist_show", "concmd_ShowAsList", ACCESS_FLAG)
	register_concmd("bg_ip_blacklist_add", "concmd_AddToIpList", ACCESS_FLAG)
	register_concmd("bg_ip_whitelist_add", "concmd_AddToIpList", ACCESS_FLAG)
	register_concmd("bg_ip_blacklist_del", "concmd_DelFromIpList", ACCESS_FLAG)
	register_concmd("bg_ip_whitelist_del", "concmd_DelFromIpList", ACCESS_FLAG)
	register_concmd("bg_ip_blacklist_show", "concmd_ShowIpList", ACCESS_FLAG)
	register_concmd("bg_ip_whitelist_show", "concmd_ShowIpList", ACCESS_FLAG)
	register_concmd("bg_find_ip", "concmd_FindIP", ACCESS_FLAG)
	register_concmd("bg_find_as", "concmd_FindAS", ACCESS_FLAG)
	register_concmd("bg_get_as_by_ip", "concmd_GetAsByIP", ACCESS_FLAG)
	register_concmd("bg_check_ip", "concmd_CheckIP", ACCESS_FLAG)
	register_concmd("bg_flush_data", "concmd_FlushData", ACCESS_FLAG)
	register_concmd("bg_status", "concmd_Status", ACCESS_FLAG)

	/* --- */

	new pCvar = get_cvar_pointer("amx_default_access")

	if(pCvar) {
		new szFlags[32]; get_pcvar_string(pCvar, szFlags, chx(szFlags))
		g_bitDefAccFlags = read_flags(szFlags)
		hook_cvar_change(pCvar, "hook_CvarChange")
		g_pCvar[PCVAR__AMX_DEFAULT_ACCESS] = pCvar
	}

	/* --- */

	new szPath[PLATFORM_MAX_PATH]

	new iLen = get_localinfo("amxx_logs", szPath, chx(szPath))
	formatex(szPath[iLen], chx(szPath) - iLen, "/%s", DIR_NAME)

	if(!dir_exists(szPath)) {
		mkdir(szPath)
	}

	for(new i; i <= LOG__ERROR; i++) {
		formatex(g_eLogFile[i], PLATFORM_MAX_PATH - 1, "%s/%s", szPath, LOG_NAME[i])
	}

	new szTime[18]

	get_time("%m.%Y_", szTime, chx(szTime))

	for(new i = LOG__DENY; i <= LOG__ALLOW; i++) {
		formatex(g_eLogFile[i], PLATFORM_MAX_PATH - 1, "%s/%s%s", szPath, szTime, LOG_NAME[i])
	}

	/* --- */

	iLen = get_localinfo("amxx_configsdir", szPath, chx(szPath))
	iLen += formatex(szPath[iLen], chx(szPath) - iLen, "/%s", DIR_NAME)

	if(!dir_exists(szPath)) {
		mkdir(szPath)
	}

	formatex(g_szIpListFile, chx(g_szIpListFile), "%s/%s", szPath, IP_FILE_NAME)
	formatex(g_szAsListFile, chx(g_szAsListFile), "%s/%s", szPath, AS_FILE_NAME)
	func_LoadRanges()
	func_LoadAsNumbers()

	formatex(szPath[iLen], chx(szPath) - iLen, "/%s", ALLOWED_COUNTRY_FILE_NAME)
	func_LoadCodes(ALLOWED_COUNTRY_FILE_NAME, szPath, g_tAllowedCodes, .bAllowed = true)

	formatex(szPath[iLen], chx(szPath) - iLen, "/%s", BANNED_COUNTRY_FILE_NAME)
	func_LoadCodes(BANNED_COUNTRY_FILE_NAME, szPath, g_tBannedCodes, .bAllowed = false)
}

/* -------------------- */

public client_putinserver(pPlayer) {
	ClearBit(g_bitSkipGeo, pPlayer);
	g_bitPlayerFailFlags[pPlayer] = 0

	g_iAccessType[pPlayer] = INVALID_ACCESS_TYPE
	g_szAccess[pPlayer] = _NA_
	g_szAccessExt[pPlayer] = _NA_
	g_szAsNumber[pPlayer] = _NA_
	g_szDesc[pPlayer] = _NA_
	g_szCode[pPlayer] = _NA_
	g_szCountry[pPlayer] = _NA_
	g_szSvStatus[pPlayer] = _NA_
	g_bSvAllowConnect[pPlayer] = false

	get_user_ip(pPlayer, g_szIP[pPlayer], chx(g_szIP[]), .without_port = 1)
	get_user_ip(pPlayer, g_szAddress[pPlayer], chx(g_szAddress[]), .without_port = 0)
	get_user_authid(pPlayer, g_szAuthID[pPlayer], chx(g_szAuthID[]))

	if(is_user_bot(pPlayer) || is_user_hltv(pPlayer)) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__BOT_OR_HLTV
		g_szAccess[pPlayer] = "Bot/HLTV"
		g_bCheckComplete[pPlayer] = true
		return
	}

	if(!g_eCvar[CVAR__PLUGIN_ENABLED]) {
		return
	}

	new Float:fCheckDelay = g_eCvar[CVAR_F__CHECK_DELAY]

	if(g_eCvar[CVAR__ALLOW_BY_STATS]) {
		// give time to load player data in stats plugin
		fCheckDelay = floatmax(1.0, fCheckDelay)
	}

	set_task(fCheckDelay, "task_CheckPlayer_Step1", get_user_userid(pPlayer))
}

/* -------------------- */

public client_disconnected(pPlayer) {
	remove_task(get_user_userid(pPlayer)) // task_CheckPlayer_Step1() and also task_DelayedKick()
}

/* -------------------- */

public client_remove(pPlayer) {
	g_bCheckComplete[pPlayer] = false
}

/* -------------------- */

FormPlayerData(pPlayer, ePlayerData[BG_PLAYER_DATA_STRUCT]) {
	ePlayerData[BG_PDS__ACCESS_TYPE] = g_iAccessType[pPlayer]
	copy(ePlayerData[BG_PDS__AS], chx(ePlayerData[BG_PDS__AS]), g_szAsNumber[pPlayer])
	copy(ePlayerData[BG_PDS__DESC], chx(ePlayerData[BG_PDS__DESC]), g_szDesc[pPlayer])
	copy(ePlayerData[BG_PDS__CODE], chx(ePlayerData[BG_PDS__CODE]), g_szCode[pPlayer])
	copy(ePlayerData[BG_PDS__COUNTRY], chx(ePlayerData[BG_PDS__COUNTRY]), g_szCountry[pPlayer])
	copy(ePlayerData[BG_PDS__ACCESS], chx(ePlayerData[BG_PDS__ACCESS]), g_szAccess[pPlayer])
	copy(ePlayerData[BG_PDS__ACCESS_EXT], chx(ePlayerData[BG_PDS__ACCESS_EXT]), g_szAccessExt[pPlayer])
	ePlayerData[BG_PDS__CHECK_FAIL_FLAGS] = g_bitPlayerFailFlags[pPlayer]
	copy(ePlayerData[BG_PDS__SV_STATUS], chx(ePlayerData[BG_PDS__SV_STATUS]), g_szSvStatus[pPlayer])
}

/* -------------------- */

SetPlayerCheckComplete(pPlayer, bool:bAllowConnect) {
	g_bCheckComplete[pPlayer] = true

	FormPlayerData(pPlayer, g_ePlayerData)

	ExecuteForward(g_fwdPlayerCheckComplete, _, pPlayer, bAllowConnect, PrepareArray(g_ePlayerData, sizeof(g_ePlayerData)))
}

/* -------------------- */

public task_CheckPlayer_Step1(iUserID) {
	new pPlayer = find_player("k", iUserID)

	if(!is_user_connected(pPlayer)/* || is_user_bot(pPlayer) || is_user_hltv(pPlayer)*/ || g_bPluginEnded) {
		return
	}

	if(g_eCvar[CVAR__COUNTRY_CHECK_MODE]) {
		// provider plugin -> _BypassGuard_SendGeoData() -> func_CheckPlayer_Step2()
		func_RequestGeoData(pPlayer, g_szIP[pPlayer])
		return
	}

	SetBit(g_bitSkipGeo, pPlayer);
	func_CheckPlayer_Step2(pPlayer)
}

/* -------------------- */

func_CheckPlayer_Step2(pPlayer) {
	if(g_eCvar[CVAR__ALLOW_STEAM] && is_user_steam(pPlayer)) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__STEAM
		g_szAccess[pPlayer] = "Steam"

		log_to_file( g_eLogFile[LOG__ALLOW], "[Legit Steam] %n | %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], g_szCode[pPlayer], g_szCountry[pPlayer] );

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	new bool:bImmunity, iFlags = get_user_flags(pPlayer)

	if(g_bitImmunityFlags) {
		if(iFlags & g_bitImmunityFlags) {
			bImmunity = true
		}
	}
	else if(g_bitDefAccFlags && !(iFlags & g_bitDefAccFlags)) {
		bImmunity = true
	}

	if(bImmunity) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__ACCESS_FLAGS
		g_szAccess[pPlayer] = "Access"

		new szFlags[32]; get_flags(iFlags, szFlags, chx(szFlags))
		copy(g_szAccessExt[pPlayer], chx(g_szAccessExt[]), szFlags)

		log_to_file( g_eLogFile[LOG__ALLOW], "[Access Flags] %n | %s | %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], szFlags, g_szCode[pPlayer], g_szCountry[pPlayer] );

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	if(nvault_get(g_hImmunity, g_szAuthID[pPlayer])) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__STEAMID_IMMUNITY
		g_szAccess[pPlayer] = "Immunity"

		log_to_file( g_eLogFile[LOG__ALLOW], "[SteamID Immunity] %n | %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], g_szCode[pPlayer], g_szCountry[pPlayer] );

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	new eRangeData[RANGE_DATA_STRUCT], iIP = func_ParseIP(g_szIP[pPlayer])

	if(IsIpInList(iIP, LIST_TYPE__WHITELIST, eRangeData)) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__IP_WHITELIST
		g_szAccess[pPlayer] = "IP Whitelist"
		new szStartIP[MAX_IP_LENGTH], szEndIP[MAX_IP_LENGTH]

		func_ReverseIP(eRangeData[RDS__START_IP], szStartIP, chx(szStartIP))
		func_ReverseIP(eRangeData[RDS__END_IP], szEndIP, chx(szEndIP))

		if(!eRangeData[RDS__COMMENT][0]) {
			eRangeData[RDS__COMMENT] = _NA_
		}

		formatex(g_szAccessExt[pPlayer], chx(g_szAccessExt[]), "%s %s ^"%s^"", szStartIP, szEndIP, eRangeData[RDS__COMMENT])

		log_to_file( g_eLogFile[LOG__ALLOW], "[IP Whitelist] %n | %s | %s | %s - %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], szStartIP, szEndIP, eRangeData[RDS__COMMENT],
			g_szCode[pPlayer], g_szCountry[pPlayer] );

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	if(CanJoinByStats(pPlayer)) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__STATS_IMMUNITY
		g_szAccess[pPlayer] = "Stats Immunity"

		log_to_file( g_eLogFile[LOG__ALLOW], "[Stats Immunity] %n | %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], g_szCode[pPlayer], g_szCountry[pPlayer] );

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	// provider plugin -> _BypassGuard_SendAsInfo() -> func_CheckPlayer_Step3()
	new iRet; ExecuteForward(g_fwdRequestAsInfo, iRet, pPlayer, g_szIP[pPlayer], g_eCvar[CVAR__MAX_CHECK_TRIES])

	if(!iRet) {
		FwdError("BypassGuard_RequestAsInfo")
	}
}

/* -------------------- */

// [0] CSstatsX SQL https://dev-cs.ru/resources/179/
//
// Returns player played time in seconds
//	@return - played time in seconds
//			-1 if no played time recorded
//
native get_user_gametime(id)

// [1] CsStats MySQL: https://fungun.net/shop/?p=show&id=3
#define _GAMETIME	14	// Время в игре (в секундах)
// Вернет значение пункта статистики(ident)
native csstats_get_user_value(id, ident)

// [2] CMSStats MySQL https://cs-games.club/index.php?resources/cmsstats-mysql.13/
/**Массив основной статистики*/
enum _:MAIN_STATS
{
	FRAGS,			/*Фраги*/
	DEATHS,			/* Смерти*/
	HEADSHOTS,		/* В голову*/
	TEAMKILLS,		/* Убийства своих*/
	SHOTS,			/* Выстрелов*/
	HITS,			/* Попаданий*/
	DAMAGE,			/* Урон*/
	PLACE			/* Место в статистике*/
}

/**Массив полной статистики*/
enum _:STATS_ARR_SIZE
{
	SUICIDE = MAIN_STATS,		/* Самоубийства*/
	DEFUSING,		/* Начал разминировать бомб*/
	DEFUSED,		/* Разминировал бомб*/
	PLANTED,		/* Поставил бомб*/
	EXPLODE,		/* Взорвал бомб*/
	LASTTIME,		/* Когда был последний раз (в UNIX времени)*/
	GAMETIME,		/* Время в игре (в секундах)*/
	CONNECTS,		/* Сыграл игр*/
	ROUNDS,			/* Сыграл раундов*/
	WINT,			/* Выиграл за Т*/
	WINCT,			/* Выиграл за СТ*/
	RESHOSTAGE,		/* Спас заложников*/
	KILLASSIST,		/* Помощь в убийстве*/
	KILLSTREAK[2],	/*Череда убийств*/
	DEATHSTREAK[2],	/*Череда смертей*/
	Float:SKILL		/* Скилл игрока*/
	, ID
}

/** Получение значения пункта статистики(ident)
* @return	Вернет значение пункта статистики (ident)
*/
native cmsstats_get_user_value(id, ident)

// [3] Simple Online Logger https://dev-cs.ru/resources/430/
native sol_get_user_time(id)

bool:CanJoinByStats(pPlayer) {
	if(!g_eCvar[CVAR__ALLOW_BY_STATS]) {
		return false
	}

	new iMinutes

	switch(g_eCvar[CVAR__STATS_TYPE]) {
		case 0: { // CSstatsX SQL https://dev-cs.ru/resources/179/
			iMinutes = get_user_gametime(pPlayer) / 60
		}
		case 1: { // CsStats MySQL: https://fungun.net/shop/?p=show&id=3
			iMinutes = csstats_get_user_value(pPlayer, _GAMETIME) / 60
		}
		case 2: { // CMSStats MySQL https://cs-games.club/index.php?resources/cmsstats-mysql.13/
			iMinutes = cmsstats_get_user_value(pPlayer, GAMETIME) / 60
		}
		case 3: { // [3] Simple Online Logger https://dev-cs.ru/resources/430/
			iMinutes = sol_get_user_time(pPlayer) / 60
		}
	}

	return (iMinutes >= g_eCvar[CVAR__ALLOW_BY_STATS])
}

/* -------------------- */

FwdError(const szFwdName[]) {
	log_to_file(g_eLogFile[LOG__ERROR], "[Error] No one handle '%s' request! Check your setup!", szFwdName)
	set_fail_state("No one handle '%s' request! Check your setup!", szFwdName)
}

/* -------------------- */

func_CheckPlayer_Step3(pPlayer) {
	new eAsTrieData[AS_DATA_STRUCT]
	TrieGetArray(g_tAsNumbers, g_szAsNumber[pPlayer], eAsTrieData, sizeof(eAsTrieData))

	if(eAsTrieData[AST__STATE] == STATE__BAN) {
		func_KickPlayer(pPlayer, KICK_TYPE__AS_BAN, eAsTrieData[AST__ARRAY_POS])
		return
	}

	new eRangeData[RANGE_DATA_STRUCT], iIP = func_ParseIP(g_szIP[pPlayer])

	if(IsIpInList(iIP, LIST_TYPE__BLACKLIST, eRangeData)) {
		func_KickPlayer(pPlayer, KICK_TYPE__IP_BAN, .eRangeData = eRangeData)
		return
	}

	if(eAsTrieData[AST__STATE] == STATE__WHITELIST) {
		g_iAccessType[pPlayer] = ALLOW_TYPE__AS_WHITELIST
		g_szAccess[pPlayer] = "AS Whitelist"

		new eAsData[AS_DATA_STRUCT]
		ArrayGetArray(Array:g_aAsArray[LIST_TYPE__WHITELIST], eAsTrieData[AST__ARRAY_POS], eAsData)

		if(!eAsData[ASD__COMMENT][0]) {
			eAsData[ASD__COMMENT] = _NA_
		}

		log_to_file( g_eLogFile[LOG__ALLOW], "[AS Whitelist] %n | %s | %s | %s | %s | %s | %s | %s",
			pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], g_szAsNumber[pPlayer], g_szDesc[pPlayer],
			eAsData[ASD__COMMENT], g_szCode[pPlayer], g_szCountry[pPlayer] );

		copy(g_szAccessExt[pPlayer], chx(g_szAccessExt[]), eAsData[ASD__COMMENT])

		func_LogPlayerFlags(pPlayer, LOG__ALLOW)

		SetPlayerCheckComplete(pPlayer, true)

		return
	}

	// provider plugin -> _BypassGuard_SendSupervisingResult() -> func_CheckPlayer_Step4()
	new iRet; ExecuteForward(g_fwdRequestSupervising, iRet, pPlayer, g_szAsNumber[pPlayer])

	if(!iRet) {
		g_bSvAllowConnect[pPlayer] = true
		func_CheckPlayer_Step4(pPlayer, false, false, false)
	}
}

/* -------------------- */

func_CheckPlayer_Step4(pPlayer, bool:bSupervisorActive, bool:bByWhitepass, bool:bStrictStatus) {
	switch(g_eCvar[CVAR__CHECK_PROXY]) {
		case 0: {
			func_CheckPlayer_Step5(pPlayer, false)
			return
		}
		case 2: {
			// if SV is running and (status is 'non-strict' or player have whitepass), we skip proxy/vpn check
			// if SV is not running, we act like bypass_guard_check_proxy have value "1"
			if(bSupervisorActive && (!bStrictStatus || bByWhitepass)) {
				func_CheckPlayer_Step5(pPlayer, false)
				return
			}
		}
	}

	// provider plugin -> _BypassGuard_SendProxyStatus() -> func_CheckPlayer_Step5()
	new iRet; ExecuteForward(g_fwdRequestProxyStatus, iRet, pPlayer, g_szIP[pPlayer], g_eCvar[CVAR__MAX_CHECK_TRIES])

	if(!iRet) {
		FwdError("BypassGuard_RequestProxyStatus")
	}
}

/* -------------------- */

func_CheckPlayer_Step5(pPlayer, bool:bIsProxy) {
	if(bIsProxy) {
		func_KickPlayer(pPlayer, KICK_TYPE__PROXY_DETECTED)
		return
	}

	if(CheckBit(g_bitSkipGeo, pPlayer) || g_eCvar[CVAR__COUNTRY_CHECK_MODE] <= 0) {
		func_CheckPlayer_Step6(pPlayer)
		return
	}

	if(CheckBit(g_bitKickFailCheckFlags, BG_CHECK_FAIL__COUNTRY) && CheckBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__COUNTRY)) {
		ClearBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__COUNTRY)
		func_KickPlayer(pPlayer, KICK_TYPE__COUNTRY_CHECK_FAIL)
		return
	}

	switch(g_eCvar[CVAR__COUNTRY_CHECK_MODE]) {
		case 1: {
			if(!TrieKeyExists(g_tAllowedCodes, g_szCode[pPlayer])) {
				func_KickPlayer(pPlayer, KICK_TYPE__BAD_COUNTRY)
				return
			}
		}
		case 2: {
			if(TrieKeyExists(g_tBannedCodes, g_szCode[pPlayer])) {
				func_KickPlayer(pPlayer, KICK_TYPE__BAD_COUNTRY)
				return
			}
		}
	}

	func_CheckPlayer_Step6(pPlayer)
}

/* -------------------- */

func_CheckPlayer_Step6(pPlayer) {
	if(g_bSvAllowConnect[pPlayer]) {
		AllowPlayerByChecks(pPlayer)
		return
	}

	func_KickPlayer(pPlayer, KICK_TYPE__SUPERVISOR)
}

/* -------------------- */

AllowPlayerByChecks(pPlayer) {
	g_iAccessType[pPlayer] = ALLOW_TYPE__CHECK
	g_szAccess[pPlayer] = "Check"

	log_to_file( g_eLogFile[LOG__ALLOW], "[%s] [SV: %s] %n | %s | %s | %s | %s | %s | %s",
		g_szAccess[pPlayer], g_szSvStatus[pPlayer], pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer], g_szAsNumber[pPlayer],
		g_szDesc[pPlayer], g_szCode[pPlayer], g_szCountry[pPlayer]
	);

	func_LogPlayerFlags(pPlayer, LOG__ALLOW)

	SetPlayerCheckComplete(pPlayer, true)
}

/* -------------------- */

func_LogPlayerFlags(pPlayer, iLogType) {
	if(!g_bitPlayerFailFlags[pPlayer]) {
		return
	}

	static szString[128]
	new iLen = formatex(szString, chx(szString), "Check fail flags:")

	if(CheckBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__AS)) {
		iLen += formatex(szString[iLen], chx(szString) - iLen, " AS,")
	}

	if(CheckBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__PROXY)) {
		iLen += formatex(szString[iLen], chx(szString) - iLen, " Proxy,")
	}

	if(CheckBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__COUNTRY)) {
		iLen += formatex(szString[iLen], chx(szString) - iLen, " Country")
	}

	if(szString[iLen - 1] == ',') {
		szString[iLen - 1] = EOS
	}

	log_to_file(g_eLogFile[iLogType], szString)

	/* Old method
	new szFlags[32]
	get_flags(g_bitPlayerFailFlags[pPlayer], szFlags, chx(szFlags))
	log_to_file(g_eLogFile[iLogType], "Check fail flags: %s", szFlags) */
}

/* -------------------- */

func_KickPlayer(pPlayer, KICK_TYPE_ENUM:iKickType, iArrayPos = 0, eRangeData[RANGE_DATA_STRUCT] = "") {
	static const KICK_TYPE[KICK_TYPE_ENUM][] = {
		"Banned AS",
		"IP Blacklist",
		"Bad Country",
		"Proxy/VPN",
		"AS Check Fail",
		"Proxy Check Fail",
		"Country Check Fail",
		"Supervisor"
	}

	g_iAccessType[pPlayer] = iKickType
	copy(g_szAccess[pPlayer], chx(g_szAccess[]), KICK_TYPE[iKickType])

	new szMsg[320]

	new iLen = formatex( szMsg, chx(szMsg), "[%s] [SV: %s] %n | %s | %s",
		KICK_TYPE[iKickType], g_szSvStatus[pPlayer], pPlayer, g_szAddress[pPlayer], g_szAuthID[pPlayer] );

	switch(iKickType) {
		case KICK_TYPE__AS_BAN: {
			new eAsData[AS_DATA_STRUCT]
			ArrayGetArray(Array:g_aAsArray[LIST_TYPE__BLACKLIST], iArrayPos, eAsData)

			if(!eAsData[ASD__COMMENT][0]) {
				eAsData[ASD__COMMENT] = _NA_
			}

			copy(g_szAccessExt[pPlayer], chx(g_szAccessExt[]), eAsData[ASD__COMMENT])

			iLen += formatex(szMsg[iLen], chx(szMsg) - iLen, " | %s | %s | %s",
				g_szAsNumber[pPlayer], g_szDesc[pPlayer], eAsData[ASD__COMMENT] );
		}
		case KICK_TYPE__IP_BAN: {
			new szStartIP[MAX_IP_LENGTH], szEndIP[MAX_IP_LENGTH]

			func_ReverseIP(eRangeData[RDS__START_IP], szStartIP, chx(szStartIP))
			func_ReverseIP(eRangeData[RDS__END_IP], szEndIP, chx(szEndIP))

			if(!eRangeData[RDS__COMMENT][0]) {
				eRangeData[RDS__COMMENT] = _NA_
			}

			formatex(g_szAccessExt[pPlayer], chx(g_szAccessExt[]), "%s %s ^"%s^"", szStartIP, szEndIP, eRangeData[RDS__COMMENT])

			iLen += formatex( szMsg[iLen], chx(szMsg) - iLen, " | %s - %s | %s | %s | %s",
				szStartIP, szEndIP, eRangeData[RDS__COMMENT], g_szAsNumber[pPlayer], g_szDesc[pPlayer] );
		}
		case KICK_TYPE__AS_CHECK_FAIL: {
			// AS and Desc not obtained, no reason to print "N/A"
		}
		// KICK_TYPE__PROXY_DETECTED, KICK_TYPE__BAD_COUNTRY,
		// KICK_TYPE__PROXY_CHECK_FAIL, KICK_TYPE__COUNTRY_CHECK_FAIL
		default: {
			iLen += formatex(szMsg[iLen], chx(szMsg) - iLen, " | %s | %s", g_szAsNumber[pPlayer], g_szDesc[pPlayer])
		}
	}

	formatex(szMsg[iLen], chx(szMsg) - iLen, " | %s | %s", g_szCode[pPlayer], g_szCountry[pPlayer])

	log_to_file(g_eLogFile[LOG__DENY], szMsg)
	func_LogPlayerFlags(pPlayer, LOG__DENY)

	engclient_print( pPlayer, engprint_console, "^n%L %n | %s | %s", pPlayer, "BG__YOUR_NAME_STEAMID_AND_IP",
		pPlayer, g_szAuthID[pPlayer], g_szIP[pPlayer] );

	if(g_eCvar[CVAR__SHOW_URL]) {
		engclient_print(pPlayer, engprint_console, "%L^n", pPlayer, "BG__URL")
	}

	new iData[1]

	if(iKickType == KICK_TYPE__AS_CHECK_FAIL || iKickType == KICK_TYPE__PROXY_CHECK_FAIL) {
		iData[0] = 1
	}

	set_task(g_eCvar[CVAR_F__KICK_DELAY], "task_DelayedKick", get_user_userid(pPlayer), iData, sizeof(iData))

	SetPlayerCheckComplete(pPlayer, false)
}

/* -------------------- */

public task_DelayedKick(iData[], iUserID) {
	new pPlayer = find_player("k", iUserID)

	if(!is_user_connected(pPlayer)) {
		return
	}

	server_cmd( "kick #%i ^"%L^"", iUserID, pPlayer,
		iData[0] ? "BG__KICK_REASON_CHECK_FAILED" : "BG__KICK_REASON_ACCESS" );
}

/* -------------------- */

public concmd_AllowSteamID(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: bg_allow_steamid <steamid> - Add immunity to all checks by SteamID")
		return PLUGIN_HANDLED
	}

	new szBuffer[64]

	read_args(szBuffer, chx(szBuffer))
	remove_quotes(szBuffer)
	trim(szBuffer)

	if(strlen(szBuffer) > MAX_AUTHID_LENGTH || !IsValidSteamID(szBuffer)) {
		console_print(pPlayer, "* Wrong SteamID specified, check your input!")
	}
	else if(nvault_get(g_hImmunity, szBuffer)) {
		console_print(pPlayer, "* SteamID '%s' already exists in immunity list!", szBuffer)
	}
	else {
		nvault_set(g_hImmunity, szBuffer, "1")
		console_print(pPlayer, "* SteamID '%s' added to immunity list", szBuffer)
		log_to_file(g_eLogFile[LOG__CMD], "Steamid '%s' added to immunity list by %N", szBuffer, pPlayer)
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_AddToAsList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szBuffer[64], iType

	read_argv(0, szBuffer, chx(szBuffer))

	if(equali(szBuffer, "bg_as_blacklist_add")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	new iArgCount = read_argc()

	if(iArgCount == 1) {
		if(iType == LIST_TYPE__BLACKLIST) {
			console_print(pPlayer, "* Usage: bg_as_blacklist_add <as_number> <^"comment^">[optional]")
		}
		else {
			console_print(pPlayer, "* Usage: bg_as_whitelist_add <as_number> <^"comment^">[optional]")
		}

		return PLUGIN_HANDLED
	}

	read_argv(1, szBuffer, chx(szBuffer))

	if(!IsValidAsNumber(szBuffer)) {
		console_print(pPlayer, "* Wrong AS number, check your input!")
		return PLUGIN_HANDLED
	}

	new eAsTrieData[AS_TRIE_STRUCT]

	if(TrieGetArray(g_tAsNumbers, szBuffer, eAsTrieData, sizeof(eAsTrieData))) {
		console_print( pPlayer, "* AS number '%s' already in %s!", szBuffer,
			LIST_NAME[ eAsTrieData[AST__STATE] == STATE__BAN ? LIST_TYPE__BLACKLIST : LIST_TYPE__WHITELIST ] );

		return PLUGIN_HANDLED
	}

	new eAsData[AS_DATA_STRUCT]

	copy(eAsData[ASD__NUMBER], MAX_AS_LEN - 1, szBuffer)

	if(iArgCount > 2) {
		read_argv(2, szBuffer, chx(szBuffer))
		trim(szBuffer)

		if(strlen(szBuffer) > MAX_COMMENT_LEN) {
			console_print(pPlayer, "* Comment is too long, max %i chars!", MAX_COMMENT_LEN)
			return PLUGIN_HANDLED
		}
	}
	else {
		szBuffer[0] = EOS
	}

	copy(eAsData[ASD__COMMENT], MAX_COMMENT_LEN - 1, szBuffer)

	new hFile = fopen(g_szAsListFile, "a")

	if(!hFile) {
		console_print(pPlayer, "* Error, can't open AS list file!")
		return PLUGIN_HANDLED
	}

	fprintf(hFile, "^n%s %s ^"%s^"", LIST_NAME[iType], eAsData[ASD__NUMBER], szBuffer)

	fclose(hFile)

	eAsTrieData[AST__STATE] = (iType == LIST_TYPE__BLACKLIST) ? STATE__BAN : STATE__WHITELIST;
	eAsTrieData[AST__ARRAY_POS] = g_iAsCount[iType]
	TrieSetArray(g_tAsNumbers, eAsData[ASD__NUMBER], eAsTrieData, sizeof(eAsTrieData))

	ArrayPushArray(g_aAsArray[iType], eAsData)
	g_iAsCount[iType]++

	console_print(pPlayer, "* AS number '%s' successfully added to %s!", eAsData[ASD__NUMBER], LIST_NAME[iType])

	log_to_file( g_eLogFile[LOG__CMD], "AS number '%s' added to %s by %N", eAsData[ASD__NUMBER],
		LIST_NAME[iType], pPlayer );

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_DelFromAsList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szBuffer[64], iType

	read_argv(0, szBuffer, chx(szBuffer))

	if(equali(szBuffer, "bg_as_blacklist_del")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	if(read_argc() == 1) {
		console_print( pPlayer, "* Usage: %s <as_number>",
			iType == LIST_TYPE__BLACKLIST ? "bg_as_blacklist_del" : "bg_as_whitelist_del" );

		return PLUGIN_HANDLED
	}

	read_argv(1, szBuffer, chx(szBuffer))

	if(!IsValidAsNumber(szBuffer)) {
		console_print(pPlayer, "* Wrong AS number, check your input!")
		return PLUGIN_HANDLED
	}

	new eAsTrieData[AS_TRIE_STRUCT]

	if(!TrieGetArray(g_tAsNumbers, szBuffer, eAsTrieData, sizeof(eAsTrieData))) {
		console_print(pPlayer, "* AS number '%s' NOT found in %s!", szBuffer, LIST_NAME[iType])
		return PLUGIN_HANDLED
	}

	TrieClear(g_tAsNumbers)
	g_iAsCount[LIST_TYPE__BLACKLIST] = 0
	g_iAsCount[LIST_TYPE__WHITELIST] = 0
	ArrayClear(Array:g_aAsArray[LIST_TYPE__BLACKLIST])
	ArrayClear(Array:g_aAsArray[LIST_TYPE__WHITELIST])

	new szOldFileName[PLATFORM_MAX_PATH]
	formatex(szOldFileName, chx(szOldFileName), "%s_old", g_szAsListFile)

	if(!rename_file(g_szAsListFile, szOldFileName, .relative = 1)) {
		console_print(pPlayer, "* Error, can't rename AS list file!")
		return PLUGIN_HANDLED
	}

	new hOldFile = fopen(szOldFileName, "r")

	if(!hOldFile) {
		console_print(pPlayer, "* Error, can't open renamed AS list file!")
		return PLUGIN_HANDLED
	}

	new hNewFile = fopen(g_szAsListFile, "w")

	if(!hNewFile) {
		fclose(hOldFile)
		console_print(pPlayer, "* Error, can't open new AS list file!")
		return PLUGIN_HANDLED
	}

	new szString[128], bool:bFound, eAsData[AS_DATA_STRUCT]

	func_AddDefSting_AS(hNewFile)

	while(!feof(hOldFile)) {
		fgets(hOldFile, szString, chx(szString))
		trim(szString)

		switch(szString[0]) {
			case 'b': iType = LIST_TYPE__BLACKLIST
			case 'w': iType = LIST_TYPE__WHITELIST
			default: continue //  ';', '/', EOS, etc.
		}

		eAsData[ASD__COMMENT][0] = EOS

		parse( szString, "", "", eAsData[ASD__NUMBER], MAX_AS_LEN - 1,
			eAsData[ASD__COMMENT], MAX_COMMENT_LEN - 1 );

		if(equal(eAsData[ASD__NUMBER], szBuffer)) {
			bFound = true
			continue
		}

		fprintf(hNewFile, "^n%s %s ^"%s^"", LIST_NAME[iType], eAsData[ASD__NUMBER], eAsData[ASD__COMMENT])

		eAsTrieData[AST__STATE] = (iType == LIST_TYPE__BLACKLIST) ? STATE__BAN : STATE__WHITELIST;
		eAsTrieData[AST__ARRAY_POS] = g_iAsCount[iType]
		TrieSetArray(g_tAsNumbers, eAsData[ASD__NUMBER], eAsTrieData, sizeof(eAsTrieData))

		ArrayPushArray(g_aAsArray[iType], eAsData)
		g_iAsCount[iType]++
	}

	fclose(hOldFile)
	fclose(hNewFile)

	if(!delete_file(szOldFileName)) {
		console_print(pPlayer, "* Warning! Can't delete '%s'", szOldFileName)
	}

	if(bFound) {
		console_print(pPlayer, "* AS number '%s' successfully removed from %s!", szBuffer, LIST_NAME[iType])
	}
	else {
		console_print(pPlayer, "* AS number '%s' removed from memory, but not found in '%s'!", szBuffer, AS_FILE_NAME)
	}

	log_to_file(g_eLogFile[LOG__CMD], "AS number '%s' removed from %s by %N", szBuffer, LIST_NAME[iType], pPlayer)

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_ShowAsList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szBuffer[64], iType

	read_argv(0, szBuffer, chx(szBuffer))

	if(equali(szBuffer, "bg_as_blacklist_show")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	new iTotalPages = floatround(float(g_iAsCount[iType]) / 10.0, floatround_ceil)

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: %s <page> (total pages: %i)",
			iType == LIST_TYPE__BLACKLIST ? "bg_as_blacklist_show" : "bg_as_whitelist_show", iTotalPages );

		return PLUGIN_HANDLED
	}

	new iPage = read_argv_int(1)

	if(iPage < 1) {
		iPage = 1
	}

	if(iPage > iTotalPages) {
		iPage = iTotalPages
	}

	if(!iPage) {
		console_print(pPlayer, "* AS %s is empty!", LIST_NAME[iType])
		return PLUGIN_HANDLED
	}

	console_print(pPlayer, "Displaying page %i/%i:", iPage, iTotalPages)
	console_print(pPlayer, "# <-> AS number <-> Comment")

	new iCount, iStartPos, i
	iStartPos = i = 10 * (iPage - 1)

	new eAsData[AS_DATA_STRUCT]

	while(i < g_iAsCount[iType]) {
		ArrayGetArray(g_aAsArray[iType], i, eAsData)

		if(!eAsData[ASD__COMMENT][0]) {
			eAsData[ASD__COMMENT] = _NA_
		}

		console_print(pPlayer, "%i <-> %s <-> %s", i + 1, eAsData[ASD__NUMBER], eAsData[ASD__COMMENT]);

		if(++iCount == 10) {
			break
		}

		i++
	}

	console_print(pPlayer, "Displayed records: %i/%i", iStartPos + iCount, g_iAsCount[iType])

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_AddToIpList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szBuffer[64], iType

	read_argv(0, szBuffer, chx(szBuffer))

	if(equali(szBuffer, "bg_ip_blacklist_add")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	new iArgCount = read_argc()

	if(iArgCount < 3) {
		console_print( pPlayer, "* Usage: %s <start_ip> <end_ip> <^"comment^">[optional]",
			iType == LIST_TYPE__BLACKLIST ? "bg_ip_blacklist_add" : "bg_ip_whitelist_add" );

		return PLUGIN_HANDLED
	}

	new szStart[MAX_IP_LENGTH], szEnd[MAX_IP_LENGTH]

	read_argv(1, szStart, chx(szStart))
	read_argv(2, szEnd, chx(szEnd))

	if(!IsIpValid(szStart) || !IsIpValid(szEnd)) {
		console_print(pPlayer, "* Wrong value, check your input!")
		return PLUGIN_HANDLED
	}

	new eRangeData[RANGE_DATA_STRUCT]

	eRangeData[RDS__START_IP] = func_ParseIP(szStart)
	eRangeData[RDS__END_IP] = func_ParseIP(szEnd)

	if((eRangeData[RDS__END_IP] - eRangeData[RDS__START_IP] + 1) < 1) {
		console_print(pPlayer, "* Start IP is lower than End IP!")
		return PLUGIN_HANDLED
	}

	if(iArgCount > 3) {
		read_argv(3, szBuffer, chx(szBuffer))
		trim(szBuffer)

		if(strlen(szBuffer) > MAX_COMMENT_LEN) {
			console_print(pPlayer, "* Comment is too long, max %i chars!", MAX_COMMENT_LEN)
			return PLUGIN_HANDLED
		}
	}
	else {
		szBuffer[0] = EOS
	}

	copy(eRangeData[RDS__COMMENT], MAX_COMMENT_LEN - 1, szBuffer)

	new hFile = fopen(g_szIpListFile, "a")

	if(!hFile) {
		console_print(pPlayer, "* Error, can't open subnet list file!")
		return PLUGIN_HANDLED
	}

	fprintf(hFile, "^n%s %s %s", LIST_NAME[iType], szStart, szEnd)

	if(szBuffer[0]) {
		fprintf(hFile, " ^"%s^"", szBuffer)
	}

	fclose(hFile)

	ArrayPushArray(g_eIpArray[iType], eRangeData)
	g_iIpCount[iType]++

	console_print( pPlayer, "* Range '%s - %s' successfully added to %s!",
		szStart, szEnd, LIST_NAME[iType] );

	log_to_file( g_eLogFile[LOG__CMD], "Range '%s - %s' added to %s by %N",
		szStart, szEnd, LIST_NAME[iType], pPlayer );

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_DelFromIpList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szCmd[64], iType

	read_argv(0, szCmd, chx(szCmd))

	if(equali(szCmd, "bg_ip_blacklist_del")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	if(read_argc() < 3) {
		console_print( pPlayer, "* Usage: %s <start_ip> <end_ip>",
			iType == LIST_TYPE__BLACKLIST ? "bg_ip_blacklist_del" : "bg_ip_whitelist_del" );

		return PLUGIN_HANDLED
	}

	new szStart[MAX_IP_LENGTH], szEnd[MAX_IP_LENGTH]

	read_argv(1, szStart, chx(szStart))
	read_argv(2, szEnd, chx(szEnd))

	if(!IsIpValid(szStart) || !IsIpValid(szEnd)) {
		console_print(pPlayer, "* Wrong value, check your input!")
		return PLUGIN_HANDLED
	}

	new iStartIP = func_ParseIP(szStart)
	new iEndIP = func_ParseIP(szEnd)

	new bool:bFound, eRangeData[RANGE_DATA_STRUCT]

	for(new i; i < g_iIpCount[iType]; i++) {
		ArrayGetArray(g_eIpArray[iType], i, eRangeData)

		if(eRangeData[RDS__START_IP] == iStartIP && eRangeData[RDS__END_IP] == iEndIP) {
			ArrayDeleteItem(g_eIpArray[iType], i)
			g_iIpCount[iType]--
			bFound = true
			break
		}
	}

	if(!bFound) {
		console_print(pPlayer, "* Record with specified values not found!")
		return PLUGIN_HANDLED
	}

	new szOldFileName[PLATFORM_MAX_PATH]
	formatex(szOldFileName, chx(szOldFileName), "%s_old", g_szIpListFile)

	if(!rename_file(g_szIpListFile, szOldFileName, .relative = 1)) {
		console_print(pPlayer, "* Error, can't rename subnet list file!")
		return PLUGIN_HANDLED
	}

	new hOldFile = fopen(szOldFileName, "r")

	if(!hOldFile) {
		console_print(pPlayer, "* Error, can't open renamed subnet list file!")
		return PLUGIN_HANDLED
	}

	new hNewFile = fopen(g_szIpListFile, "w")

	if(!hNewFile) {
		fclose(hOldFile)
		console_print(pPlayer, "* Error, can't open new subnet list file!")
		return PLUGIN_HANDLED
	}

	func_AddDefSting_List(hNewFile)

	new iCfgType, szBuffer[128], szOldStart[MAX_IP_LENGTH], szOldEnd[MAX_IP_LENGTH], szComment[MAX_COMMENT_LEN]

	bFound = false

	while(!feof(hOldFile)) {
		fgets(hOldFile, szBuffer, chx(szBuffer))
		trim(szBuffer)

		switch(szBuffer[0]) {
			case 'b': iCfgType = LIST_TYPE__BLACKLIST
			case 'w': iCfgType = LIST_TYPE__WHITELIST
			default: continue //  ';', '/', EOS, etc.
		}

		szComment[0] = EOS

		parse(szBuffer, "", "", szOldStart, chx(szOldStart), szOldEnd, chx(szOldEnd), szComment, MAX_COMMENT_LEN - 1)

		if(equal(szStart, szOldStart) && equal(szEnd, szOldEnd) && iType == iCfgType) {
			bFound = true
			continue
		}

		fprintf(hNewFile, "^n%s %s %s", LIST_NAME[iCfgType], szOldStart, szOldEnd)

		if(szComment[0]) {
			fprintf(hNewFile, " ^"%s^"", szComment)
		}
	}

	fclose(hOldFile)
	fclose(hNewFile)

	if(!delete_file(szOldFileName)) {
		console_print(pPlayer, "* Warning! Can't delete '%s'", szOldFileName)
	}

	if(bFound) {
		console_print(pPlayer, "* Range '%s - %s' successfully removed from %s!", szStart, szEnd, LIST_NAME[iType])
	}
	else {
		console_print(pPlayer, "* Range '%s - %s' removed from %s, but not found in subnet list file!", szStart, szEnd, LIST_NAME[iType])
	}

	log_to_file(g_eLogFile[LOG__CMD], "Range '%s - %s' removed from %s by %N", szStart, szEnd, LIST_NAME[iType], pPlayer)

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_ShowIpList(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	new szBuffer[64], iType

	read_argv(0, szBuffer, chx(szBuffer))

	if(equali(szBuffer, "bg_ip_blacklist_show")) {
		iType = LIST_TYPE__BLACKLIST
	}
	else {
		iType = LIST_TYPE__WHITELIST
	}

	new iTotalPages = floatround(float(g_iIpCount[iType]) / 10.0, floatround_ceil)

	if(read_argc() == 1) {
		console_print( pPlayer, "* Usage: %s <page> (total pages: %i)",
			iType == LIST_TYPE__BLACKLIST ? "bg_ip_blacklist_show" : "bg_ip_whitelist_show", iTotalPages );

		return PLUGIN_HANDLED
	}

	new iPage = read_argv_int(1)

	if(iPage < 1) {
		iPage = 1
	}

	if(iPage > iTotalPages) {
		iPage = iTotalPages
	}

	if(!iPage) {
		console_print(pPlayer, "* IP %s is empty!", LIST_NAME[iType])
		return PLUGIN_HANDLED
	}

	console_print(pPlayer, "Displaying page %i/%i:", iPage, iTotalPages)
	console_print(pPlayer, "# <-> StartIP <-> EndIP <-> Comment")

	new iCount, iStartPos, i
	iStartPos = i = 10 * (iPage - 1)

	new szStartIP[MAX_IP_LENGTH], szEndIP[MAX_IP_LENGTH], eRangeData[RANGE_DATA_STRUCT]

	while(i < g_iIpCount[iType]) {
		ArrayGetArray(g_eIpArray[iType], i, eRangeData)

		func_ReverseIP(eRangeData[RDS__START_IP], szStartIP, chx(szEndIP))
		func_ReverseIP(eRangeData[RDS__END_IP], szEndIP, chx(szEndIP))

		if(!eRangeData[RDS__COMMENT][0]) {
			eRangeData[RDS__COMMENT] = _NA_
		}

		console_print( pPlayer, "%i <-> %s <-> %s <-> %s", i + 1,
			szStartIP, szEndIP, eRangeData[RDS__COMMENT] );

		if(++iCount == 10) {
			break
		}

		i++
	}

	console_print(pPlayer, "Displayed records: %i/%i", iStartPos + iCount, g_iIpCount[iType])

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_FindIP(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: bg_find_ip <ip> - Check IP presence in blacklist and whitelist")
		return PLUGIN_HANDLED
	}

	new szBuffer[64]

	read_args(szBuffer, chx(szBuffer))
	remove_quotes(szBuffer)
	trim(szBuffer)

	if(!IsIpValid(szBuffer)) {
		console_print(pPlayer, "* Wrong IP, check your input!")
		return PLUGIN_HANDLED
	}

	new eRangeData[RANGE_DATA_STRUCT], iIP = func_ParseIP(szBuffer)
	new szStartIP[MAX_IP_LENGTH], szEndIP[MAX_IP_LENGTH]

	for(new iType = LIST_TYPE__BLACKLIST; iType <= LIST_TYPE__WHITELIST; iType++) {
		if(IsIpInList(iIP, iType, eRangeData)) {
			console_print(pPlayer, "* IP '%s' FOUND in %s", szBuffer, LIST_NAME[iType])

			func_ReverseIP(eRangeData[RDS__START_IP], szStartIP, chx(szStartIP))
			func_ReverseIP(eRangeData[RDS__END_IP], szEndIP, chx(szEndIP))

			if(!eRangeData[RDS__COMMENT][0]) {
				eRangeData[RDS__COMMENT] = _NA_
			}

			console_print( pPlayer, "* Range '%s <-> %s', comment: '%s'",
				szStartIP, szEndIP, eRangeData[RDS__COMMENT] );

			continue
		}

		console_print(pPlayer, "* IP '%s' NOT found in %s", szBuffer, LIST_NAME[iType])
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_FindAS(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: bg_find_as <as_number> - Check AS number presence in blacklist and whitelist")
		return PLUGIN_HANDLED
	}

	new szBuffer[64]

	read_args(szBuffer, chx(szBuffer))
	remove_quotes(szBuffer)
	trim(szBuffer)

	if(!IsValidAsNumber(szBuffer)) {
		console_print(pPlayer, "* Wrong AS number, check your input!")
		return PLUGIN_HANDLED
	}

	if(!TrieKeyExists(g_tAsNumbers, szBuffer)) {
		console_print(pPlayer, "* AS number '%s' NOT found in both lists!", szBuffer)
		return PLUGIN_HANDLED
	}

	new eAsData[AS_DATA_STRUCT]

	for(new iType = LIST_TYPE__BLACKLIST; iType <= LIST_TYPE__WHITELIST; iType++) {
		for(new i; i < g_iAsCount[iType]; i++) {
			ArrayGetArray(g_aAsArray[iType], i, eAsData)

			if(equal(eAsData[ASD__NUMBER], szBuffer)) {
				if(!eAsData[ASD__COMMENT][0]) {
					eAsData[ASD__COMMENT] = _NA_
				}

				console_print( pPlayer, "* AS number '%s' FOUND in %s, comment: '%s'",
					szBuffer, LIST_NAME[iType], eAsData[ASD__COMMENT] );

				return PLUGIN_HANDLED
			}
		}
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_GetAsByIP(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: bg_get_as_by_ip <ip> - Get AS number for specified IP")
		return PLUGIN_HANDLED
	}

	new szBuffer[64]

	read_args(szBuffer, chx(szBuffer))
	remove_quotes(szBuffer)
	trim(szBuffer)

	if(!IsIpValid(szBuffer)) {
		console_print(pPlayer, "* Wrong IP, check your input!")
		return PLUGIN_HANDLED
	}

	// NOTE: Below schema based on cache in provider plugin. After request was sent, provider
	// must return data instantly, if it exists in cache (so, g_bGotInfo will be set to true)

	g_bGotInfo = false
	g_pRequestAdmin = pPlayer
	copy(g_szCmdIP, chx(g_szCmdIP), szBuffer)
	new iRet; ExecuteForward(g_fwdRequestAsInfo, iRet, 0, szBuffer, g_eCvar[CVAR__MAX_CHECK_TRIES])

	if(!iRet) {
		console_print(pPlayer, "* Error! See '%s' for more information!", LOG_NAME[LOG__ERROR])
		FwdError("BypassGuard_RequestAsInfo")
		return PLUGIN_HANDLED
	}

	if(!g_bGotInfo) {
		console_print(pPlayer, "* Query for IP '%s' was sent, use cmd again!", szBuffer)
		log_to_file(g_eLogFile[LOG__CMD], "GetAS request for '%s' by %N", szBuffer, pPlayer)
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_CheckIP(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() == 1) {
		console_print(pPlayer, "* Usage: bg_check_ip <ip> - Check IP for proxy/VPN")
		return PLUGIN_HANDLED
	}

	new szBuffer[64]

	read_args(szBuffer, chx(szBuffer))
	remove_quotes(szBuffer)
	trim(szBuffer)

	if(!IsIpValid(szBuffer)) {
		console_print(pPlayer, "* Wrong IP, check your input!")
		return PLUGIN_HANDLED
	}

	// NOTE: Below schema based on cache in provider plugin. After request was sent, provider
	// must return data instantly, if it exists in cache (so, g_bGotInfo will be set to true)

	g_bGotInfo = false
	g_pRequestAdmin = pPlayer
	copy(g_szCmdIP, chx(g_szCmdIP), szBuffer)
	new iRet; ExecuteForward(g_fwdRequestProxyStatus, iRet, 0, szBuffer, g_eCvar[CVAR__MAX_CHECK_TRIES])

	if(!iRet) {
		console_print(pPlayer, "* Error! See '%s' for more information!", LOG_NAME[LOG__ERROR])
		FwdError("BypassGuard_RequestProxyStatus")
		return PLUGIN_HANDLED
	}

	if(!g_bGotInfo) {
		console_print(pPlayer, "* Query for IP '%s' was sent, use cmd again!", szBuffer)
		log_to_file(g_eLogFile[LOG__CMD], "CheckIP request for '%s' by %N", szBuffer, pPlayer)
	}

	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_FlushData(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(read_argc() != 1) {
		log_to_file(g_eLogFile[LOG__CMD], "Flush cmd with param '%i' by %N", read_argv_int(1), pPlayer)

		switch(read_argv_int(1)) {
			case 1: {
				nvault_prune(g_hImmunity, 0, get_systime())
				console_print(pPlayer, "* SteamID immunity data flushed!")
				return PLUGIN_HANDLED
			}
			case 2: {
				g_iIpCount[LIST_TYPE__BLACKLIST] = 0
				g_iIpCount[LIST_TYPE__WHITELIST] = 0
				ArrayClear(Array:g_eIpArray[LIST_TYPE__BLACKLIST])
				ArrayClear(Array:g_eIpArray[LIST_TYPE__WHITELIST])

				new hFile = fopen(g_szIpListFile, "w")

				if(hFile) {
					func_AddDefSting_List(hFile)
					console_print(pPlayer, "* IP range configuration flushed!")
					fclose(hFile)
				}
				else {
					console_print(pPlayer, "* Can't open '%s'!", IP_FILE_NAME)
				}

				return PLUGIN_HANDLED
			}
			case 3: {
				g_iAsCount[LIST_TYPE__BLACKLIST] = 0
				g_iAsCount[LIST_TYPE__WHITELIST] = 0
				TrieClear(g_tAsNumbers)
				ArrayClear(Array:g_aAsArray[LIST_TYPE__BLACKLIST])
				ArrayClear(Array:g_aAsArray[LIST_TYPE__WHITELIST])

				new hFile = fopen(g_szAsListFile, "w")

				if(hFile) {
					func_AddDefSting_AS(hFile)
					console_print(pPlayer, "* AS configuraion and check status cache flushed!")
					fclose(hFile)
				}
				else {
					console_print(pPlayer, "* Can't truncate '%s'!", AS_FILE_NAME)
				}

				return PLUGIN_HANDLED
			}
		}
	}

	console_print(pPlayer, "* Usage: bg_flush_data <1-3>")
	console_print(pPlayer, "* 1 - SteamID immunity list (nvault)")
	console_print(pPlayer, "* 2 - IP range configuration (memory + file)")
	console_print(pPlayer, "* 3 - AS configuration (memory + file)")
	return PLUGIN_HANDLED
}

/* -------------------- */

public concmd_Status(pPlayer, iAccess) {
	if(!UserHasAccess(pPlayer, iAccess)) {
		return PLUGIN_HANDLED
	}

	if(!g_eCvar[CVAR__PLUGIN_ENABLED]) {
		console_print(pPlayer, "* Plugin disabled, command unavailable!")
		return PLUGIN_HANDLED
	}

	console_print( pPlayer,
		"^nPlayers status:^n# <-> Access <-> Nick <-> IP <-> SteamID <-> AS <-> Desc. <-> Code <-> Country" );

	new iCount

	for(new pUser = 1; pUser <= MaxClients; pUser++) {
		if(!is_user_connected(pUser)) {
			continue
		}

		console_print( pPlayer, "%i <-> %s <-> %n <-> %s <-> %s <-> %s <-> %s <-> %s <-> %s",
			++iCount, g_szAccess[pUser], pUser, g_szAddress[pUser], g_szAuthID[pUser], g_szAsNumber[pUser],
			g_szDesc[pUser], g_szCode[pUser], g_szCountry[pUser] );
	}

	console_print(pPlayer, "Total: %i^n", iCount)

	return PLUGIN_HANDLED
}

/* -------------------- */

func_LoadRanges() {
	new hFile = fopen(g_szIpListFile, "r")

	if(!hFile) {
		if(file_exists(g_szIpListFile)) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't open existing '%s'", IP_FILE_NAME)
			return
		}

		hFile = fopen(g_szIpListFile, "w")

		if(!hFile) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't create default '%s'", IP_FILE_NAME)
			return
		}

		func_AddDefSting_List(hFile)
		fclose(hFile)
		return
	}

	new iType, szStartIP[MAX_IP_LENGTH], szEndIP[MAX_IP_LENGTH],
		szBuffer[128], eRangeData[RANGE_DATA_STRUCT];

	while(!feof(hFile)) {
		fgets(hFile, szBuffer, chx(szBuffer))
		trim(szBuffer)

		switch(szBuffer[0]) {
			case 'b': iType = LIST_TYPE__BLACKLIST
			case 'w': iType = LIST_TYPE__WHITELIST
			default: continue //  ';', '/', EOS, etc.
		}

		eRangeData[RDS__COMMENT][0] = EOS

		parse( szBuffer, "", "", szStartIP, chx(szStartIP), szEndIP, chx(szEndIP),
			eRangeData[RDS__COMMENT], MAX_COMMENT_LEN - 1 );

		eRangeData[RDS__START_IP] = func_ParseIP(szStartIP)
		eRangeData[RDS__END_IP] = func_ParseIP(szEndIP)

		ArrayPushArray(g_eIpArray[iType], eRangeData)
		g_iIpCount[iType]++
	}

	fclose(hFile)
}

/* -------------------- */

func_LoadAsNumbers() {
	new hFile = fopen(g_szAsListFile, "r")

	if(!hFile) {
		if(file_exists(g_szAsListFile)) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't open existing '%s'", AS_FILE_NAME)
			return
		}

		hFile = fopen(g_szAsListFile, "w")

		if(!hFile) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't create default '%s'", AS_FILE_NAME)
			return
		}

		func_AddDefSting_AS(hFile)
		fclose(hFile)
		return
	}

	new iType, szBuffer[128], eAsData[AS_DATA_STRUCT], eAsTrieData[AS_TRIE_STRUCT]

	while(!feof(hFile)) {
		fgets(hFile, szBuffer, chx(szBuffer))
		trim(szBuffer)

		switch(szBuffer[0]) {
			case 'b': iType = LIST_TYPE__BLACKLIST
			case 'w': iType = LIST_TYPE__WHITELIST
			default: continue //  ';', '/', EOS, etc.
		}

		eAsData[ASD__COMMENT][0] = EOS

		parse( szBuffer, "", "", eAsData[ASD__NUMBER], MAX_AS_LEN - 1,
			eAsData[ASD__COMMENT], MAX_COMMENT_LEN - 1 );

		eAsTrieData[AST__STATE] = (iType == LIST_TYPE__BLACKLIST) ? STATE__BAN : STATE__WHITELIST;
		eAsTrieData[AST__ARRAY_POS] = g_iAsCount[iType]
		TrieSetArray(g_tAsNumbers, eAsData[ASD__NUMBER], eAsTrieData, sizeof(eAsTrieData))
		ArrayPushArray(g_aAsArray[iType], eAsData)
		g_iAsCount[iType]++
	}

	fclose(hFile)
}

/* -------------------- */

func_LoadCodes(const szFileName[], szPath[], Trie:tTrie, bool:bAllowed) {
	new hFile = fopen(szPath, "r")

	if(!hFile) {
		if(file_exists(szPath)) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't open existing '%s'", szFileName)
			return
		}

		hFile = fopen(szPath, "w")

		if(!hFile) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't create default '%s'", szFileName)
			return
		}

		if(bAllowed) {
			fputs( hFile,
				"; Список стран, которые могут входить на сервер | https://www.artlebedev.ru/country-list/^n\
				; Country list that can enter to the server | https://www.iban.com/country-codes^n\
				;^n\
				;^"N/A^" // Неизвестно^n\
				^"RU^" // Россия^n\
				^"UA^" // Украина^n\
				^"BY^" // Беларусь^n\
				^"KZ^" // Казахстан^n\
				^"KG^" // Киргизия^n\
				^"MD^" // Молдавия^n\
				^"UZ^" // Узбекистан^n\
				^"LV^" // Латвия^n\
				^"LT^" // Литва^n\
				^"EE^" // Эстония^n\
				^"GE^" // Грузия^n\
				^"RO^" // Румыния^n\
				^"AM^" // Армения^n\
				^"BG^" // Болгария^n\
				^"AZ^" // Азербайджан^n\
				^"TM^" // Туркменистан^n\
				^"TJ^" // Таджикистан"
			);
		}
		else {
			fputs( hFile,
				"; Список стран, которые НЕ могут входить на сервер | https://www.artlebedev.ru/country-list/^n\
				; Country list that can't enter to the server | https://www.iban.com/country-codes^n\
				;^n\
				;^"N/A^" // Неизвестно^n\
				^"EG^" // Египет^n\
				^"GR^" // Греция"
			);
		}

		fclose(hFile)

		hFile = fopen(szPath, "r")

		if(!hFile) {
			log_to_file(g_eLogFile[LOG__ERROR], "[Error] Can't open existing '%s'", szFileName)
			return
		}
	}

	new szBuffer[32], szCode[ sizeof(_NA_) ]

	while(!feof(hFile)) {
		fgets(hFile, szBuffer, chx(szBuffer))

		if(szBuffer[0] != '"') {
			continue
		}

		parse(szBuffer, szCode, chx(szCode))
		TrieSetCell(tTrie, szCode, 0)
	}

	fclose(hFile)
}

/* -------------------- */

func_ParseIP(szIP[]) {
	new szRight[MAX_IP_LENGTH], szPart[4], iIP, iOctet

	strtok(szIP, szPart, chx(szPart), szRight, chx(szRight), '.')

	for(new i; i < 4; i++) {
		iOctet = str_to_num(szPart)

		if(iOctet < 0) {
			iOctet = 0
		}
		else if(iOctet > 255) {
			iOctet = 255
		}

		iIP += iOctet

		if(i == 3) {
			break
		}

		strtok(szRight, szPart, chx(szPart), szRight, chx(szRight), '.')
		iIP = iIP << 8
	}

	return iIP
}

/* -------------------- */

func_ReverseIP(iIP, szIP[MAX_IP_LENGTH], iLen) {
	new iOctet[4], bool:bHigh

	if(iIP < 0) {
		bHigh = true;
		iIP = iIP & (~(1 << 31));
	}

	for(new i = 0; i < 4; i++) {
		iOctet[i] = iIP & 255;
		iIP = iIP >> 8;
	}
	if(bHigh) {
		iOctet[3] += 128
	}

	formatex(szIP, iLen, "%i.%i.%i.%i", iOctet[3], iOctet[2], iOctet[1], iOctet[0])
}

/* -------------------- */

bool:IsIpInList(iIP, iType, eRangeData[RANGE_DATA_STRUCT]) {
	for(new i; i < g_iIpCount[iType]; i++) {
		ArrayGetArray(g_eIpArray[iType], i, eRangeData)

		if(
			CompareUnsigned(eRangeData[RDS__START_IP], iIP) <= 0
				&&
			CompareUnsigned(eRangeData[RDS__END_IP], iIP) >= 0
		) {
			return true
		}
	}

	return false
}

/* -------------------- */

/**
 * Compares two integers as unsigned values.
 *
 * @param	first	First value to compare.
 * @param	second	Second value to compare.
 * @return			-1 if first is smaller than second.
 *					 0 if first is equal to second.
 *					 1 if first is greater than second.
 */
CompareUnsigned(first, second) {
	if(first == second) {
		return 0
	}

	new bool:highFirst, bool:highSecond

	if(first < 0) {
		highFirst = true
		first = first & (~(1 << 31))
	}

	if(second < 0) {
		highSecond = true
		second = second & (~(1 << 31))
	}

	if(highFirst && !highSecond) {
		return 1
	}

	if(!highFirst && highSecond) {
		return -1
	}

	if(first > second) {
		return 1
	}

	return -1
}

/* -------------------- */

public hook_CvarChange(pCvar, szOldVal[], szNewVal[]) {
	new iNewVal = read_flags(szNewVal)

	if(pCvar == g_pCvar[PCVAR__AMX_DEFAULT_ACCESS]) {
		g_bitDefAccFlags = iNewVal
		return
	}

	if(pCvar == g_pCvar[PCVAR__IMMUNITY_FLAGS]) {
		g_bitImmunityFlags = iNewVal
		return
	}

	// PCVAR__KICK_IF_CANT_CHECK
	g_bitKickFailCheckFlags = iNewVal
}

/* -------------------- */

bool:IsIpValid(szIP[]) {
	new i, szRight[MAX_IP_LENGTH], szPart[4], iCount

	strtok(szIP, szPart, chx(szPart), szRight, chx(szRight), '.')

	while(szPart[0] >= '0' && szPart[0] <= '9')	{
		i = str_to_num(szPart)

		if(i < 0 || i > 255) {
			return false
		}

		iCount++
		strtok(szRight, szPart, chx(szPart), szRight, chx(szRight), '.')
	}

	return (iCount == 4)
}

/* -------------------- */

bool:IsValidSteamID(szAuthID[]) {
	// STEAM_ or VALVE_
	// 0:(0|1):\d+
	// 0-5 = STEAM_
	// 6 = integer
	// 7 = :
	// 8 = integer
	// 9 = :
	// 10+ = integer
	return (
		( equal(szAuthID, "STEAM_", 6) || equal(szAuthID, "VALVE_", 6) )
			&&
		isdigit(szAuthID[6])
		/*	&&
		szAuthID[7] == ':'
			&&
		isdigit(szAuthID[8])
			&&
		szAuthID[9] == ':'
			&&
		is_str_num(szAuthID[10])*/
	);
}

/* -------------------- */

bool:IsValidAsNumber(szAsNumber[]) {
	//As we use trie, we need case-sensitive comparement
	//if((szAsNumber[0] != 'A' && szAsNumber[0] != 'a') || (szAsNumber[1] != 'S' && szAsNumber[1] != 's') || !szAsNumber[2]) {
	if(szAsNumber[0] != 'A' || szAsNumber[1] != 'S' || !szAsNumber[2]) {
		return false
	}

	for(new i = 2; i < MAX_AS_LEN; i++) {
		if(!szAsNumber[i]) {
			return true
		}

		if(szAsNumber[i] < '0' || szAsNumber[i] > '9') {
			return false
		}
	}

	return false
}

/* -------------------- */

func_AddDefSting_List(hFile) {
	fputs(hFile, "; Формат записей / Line format:^n\
		; blacklist/whitelist start_ip end_ip ^"comment^"[optional]^n\
		; Примеры / Examples:^n\
		; blacklist 100.50.33.0 10.50.34.0 ^"cheater^"^n\
		; blacklist 60.40.0.0 60.90.25.0 ^"^"^n\
		; whitelist 162.54.22.25 162.54.48.0 ^"trusted network^"^n\
		;"
	);
}

/* -------------------- */

func_AddDefSting_AS(hFile) {
	fputs( hFile, "; Формат записей / Line format:^n\
		; blacklist/whitelist AS_number ^"comment^"[optional]^n\
		; Примеры / Examples:^n\
		; blacklist AS1234 ^"cheater^"^n\
		; blacklist AS6767 ^"^"^n\
		; whitelist AS8765 ^"good player^"^n\
		;"
	);
}

/* -------------------- */

func_RequestGeoData(pPlayer, szIP[]) {
	// provider plugin -> _BypassGuard_SendGeoData()
	new iRet; ExecuteForward(g_fwdRequestGeoData, iRet, pPlayer, szIP, g_eCvar[CVAR__MAX_CHECK_TRIES])

	if(!iRet) {
		FwdError("BypassGuard_RequestGeoData")
	}
}

/* -------------------- */

bool:UserHasAccess(pPlayer, iAccess) {
	if(get_user_flags(pPlayer) & iAccess) {
		return true
	}

	console_print(pPlayer, "* You have no access to this command!")
	return false
}

/* -------------------- */

#if !defined _reapi_included
	stock is_user_steam(pPlayer) {
		static dp_pointer

		if(dp_pointer || (dp_pointer = get_cvar_pointer("dp_r_id_provider"))) {
			server_cmd("dp_clientinfo %d", pPlayer)
			server_exec()
			return (get_pcvar_num(dp_pointer) == 2) ? 1 : 0
		}

		return 0
	}
#endif

/* -------------------- */

public plugin_end() {
	g_bPluginEnded = true

	if(g_hImmunity != INVALID_HANDLE) {
		nvault_close(g_hImmunity)
		ArrayDestroy(Array:g_eIpArray[LIST_TYPE__BLACKLIST])
		ArrayDestroy(Array:g_eIpArray[LIST_TYPE__WHITELIST])
		ArrayDestroy(Array:g_aAsArray[LIST_TYPE__BLACKLIST])
		ArrayDestroy(Array:g_aAsArray[LIST_TYPE__WHITELIST])
		TrieDestroy(g_tAsNumbers)
		TrieDestroy(g_tAllowedCodes)
		TrieDestroy(g_tBannedCodes)
	}
}

/* -------------------- */

public plugin_natives() {
	register_library("bypass_guard_core")

	set_native_filter("native_filter")

	register_native("BypassGuard_SendGeoData", "_BypassGuard_SendGeoData")
	register_native("BypassGuard_SendAsInfo", "_BypassGuard_SendAsInfo")
	register_native("BypassGuard_SendProxyStatus", "_BypassGuard_SendProxyStatus")
	register_native("BypassGuard_SendSupervisingResult", "_BypassGuard_SendSupervisingResult")
	register_native("BypassGuard_LogError", "_BypassGuard_LogError")
	register_native("BypassGuard_GetPluginFolderName", "_BypassGuard_GetPluginFolderName")
	register_native("BypassGuard_GetPlayerData", "_BypassGuard_GetPlayerData")
	register_native("BypassGuard_IsPlayerChecked", "_BypassGuard_IsPlayerChecked")
}

/* -------------------- */

public _BypassGuard_SendGeoData(iPluginID, iParamCount) {
	enum { player = 1, code, country, success }

	new pPlayer = get_param(player)

	if(get_param(success)) {
		get_string(code, g_szCode[pPlayer], chx(g_szCode[]))
		strtoupper(g_szCode[pPlayer]) // 1.0.9 fix
		get_string(country, g_szCountry[pPlayer], chx(g_szCountry[]))
	}
	else if(pPlayer) {
		SetBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__COUNTRY)
	}

	if(pPlayer) {
		func_CheckPlayer_Step2(pPlayer)
	}
}

/* -------------------- */

public _BypassGuard_SendAsInfo(iPluginID, iParamCount) {
	enum { player = 1, as, desc, success }

	new pPlayer = get_param(player)

	// NOTE: this case suppose that data was taken from cache (instantly after request)
	// for 'bg_get_as_by_ip' command
	if(!pPlayer) {
		g_bGotInfo = true

		new szAsNumber[MAX_AS_LEN], szDesc[MAX_DESC_LEN]

		get_string(as, szAsNumber, chx(szAsNumber))
		get_string(desc, szDesc, chx(szDesc))

		if(!szDesc[0]) {
			szDesc = _NA_
		}

		g_szCode[0] = _NA_
		g_szCountry[0] = _NA_

		if(g_eCvar[CVAR__COUNTRY_CHECK_MODE]) {
			func_RequestGeoData(0, g_szCmdIP)
		}

		console_print( g_pRequestAdmin, "* AS number for '%s' (%s, %s) is '%s'",
			g_szCmdIP, g_szCode[0], g_szCountry[0], szAsNumber );

		console_print(g_pRequestAdmin, "* Provider is '%s'", szDesc)

		return
	}

	if(!get_param(success)) {
		if(CheckBit(g_bitKickFailCheckFlags, BG_CHECK_FAIL__AS)) {
			func_KickPlayer(pPlayer, KICK_TYPE__AS_CHECK_FAIL)
			return
		}

		SetBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__AS)
	}
	else {
		get_string(as, g_szAsNumber[pPlayer], chx(g_szAsNumber[]))

		new szDesc[MAX_DESC_LEN]
		get_string(desc, szDesc, chx(szDesc))

		if(szDesc[0]) {
			copy(g_szDesc[pPlayer], chx(g_szDesc[]), szDesc)
		}
	}

	func_CheckPlayer_Step3(pPlayer)
}

/* -------------------- */

public _BypassGuard_SendProxyStatus(iPluginID, iParamCount) {
	enum { player = 1, is_proxy, success }

	new pPlayer = get_param(player)

	// NOTE: this case suppose that data was taken from cache (instantly after request)
	// for 'bg_check_ip' command
	if(!pPlayer) {
		g_bGotInfo = true

		static const szStatus[/*bool*/][] = { "Normal", "Proxy/VPN" }

		g_szCode[0] = _NA_
		g_szCountry[0] = _NA_

		if(g_eCvar[CVAR__COUNTRY_CHECK_MODE]) {
			func_RequestGeoData(0, g_szCmdIP)
		}

		console_print( g_pRequestAdmin, "* '%s' (%s, %s) status is '%s'",
			g_szCmdIP, g_szCode[0], g_szCountry[0], szStatus[ get_param(is_proxy) ] );

		return
	}

	if(!get_param(success)) {
		if(CheckBit(g_bitKickFailCheckFlags, BG_CHECK_FAIL__PROXY)) {
			func_KickPlayer(pPlayer, KICK_TYPE__PROXY_CHECK_FAIL)
			return
		}

		SetBit(g_bitPlayerFailFlags[pPlayer], BG_CHECK_FAIL__PROXY)
	}

	func_CheckPlayer_Step5(pPlayer, bool:get_param(is_proxy))
}

/* -------------------- */

public _BypassGuard_SendSupervisingResult(iPluginID, iParamCount) {
	enum { player = 1, allow_connect, sv_status, by_whitepass, strict_status }

	new pPlayer = get_param(player)
	get_string(sv_status, g_szSvStatus[pPlayer], charsmax(g_szSvStatus[]))

	g_bSvAllowConnect[pPlayer] = bool:get_param(allow_connect)

	func_CheckPlayer_Step4(pPlayer, true, bool:get_param(by_whitepass), bool:get_param(strict_status))
}

/* -------------------- */

public _BypassGuard_LogError(iPluginID, iParamCount) {
	enum { error_text = 1 }

	new szText[MAX_RESPONSE_LEN]
	get_string(error_text, szText, chx(szText))
	log_to_file(g_eLogFile[LOG__ERROR], szText)
}

/* -------------------- */

public _BypassGuard_GetPluginFolderName(iPluginID, iParamCount) {
	enum { data_buffer = 1, maxlen }
	set_string(data_buffer, DIR_NAME, get_param(maxlen))
	//#pragma unused data_buffer
}

/* -------------------- */

public _BypassGuard_GetPlayerData(iPluginID, iParamCount) {
	enum { player = 1, data_array }

	new pPlayer = get_param(player)

	if(!is_user_connected(pPlayer)) {
		return -1
	}

	if(!g_bCheckComplete[pPlayer]) {
		return 0
	}

	FormPlayerData(pPlayer, g_ePlayerData)

	set_array(data_array, g_ePlayerData, sizeof(g_ePlayerData))

	return 1
}

/* -------------------- */

public bool:_BypassGuard_IsPlayerChecked(iPluginID, iParamCount) {
	enum { player = 1 }
	return g_bCheckComplete[ get_param(player) ]
}

/* -------------------- */

public native_filter(const szNativeName[], iNativeID, iTrapMode) {
	return PLUGIN_HANDLED
}