#if defined _bypass_guard_included
    #endinput
#endif
#define _bypass_guard_included

#if AMXX_VERSION_NUM >= 175
    #pragma reqlib bypass_guard_core
    #if !defined AMXMODX_NOAUTOLOAD
        #pragma loadlib bypass_guard_core
    #endif
#else
    #pragma library bypass_guard_core
#endif

#define MAX_COUNTRY_LEN 64
#define MAX_CODE_LEN 3
#define MAX_AS_LEN 16
#define MAX_DESC_LEN 64
#define MAX_RESPONSE_LEN 256
#define MAX_ACCESS_LEN 32
#define MAX_ACCESS_EXT_LEN 128
#define MAX_SV_STATUS_LEN 64
#define INVALID_ACCESS_TYPE -1

stock const _NA_[] = "N/A" // don't change this!

// Note that this is not bits. If you will need to use this, you probably will need to use CheckBit/SetBit/ClearBit (see in bypass_guard.sma)
// or manually shift this values via (1<<VALUE)
enum _:BG_CHECK_FAIL_FLAGS {
	BG_CHECK_FAIL__AS,
	BG_CHECK_FAIL__PROXY,
	BG_CHECK_FAIL__COUNTRY
}

enum _:ALLOW_TYPE_ENUM {
	ALLOW_TYPE__BOT_OR_HLTV,
	ALLOW_TYPE__STEAM,
    ALLOW_TYPE__ACCESS_FLAGS,
    ALLOW_TYPE__STEAMID_IMMUNITY,
    ALLOW_TYPE__IP_WHITELIST,
    ALLOW_TYPE__STATS_IMMUNITY,
    ALLOW_TYPE__AS_WHITELIST,
    ALLOW_TYPE__CHECK
}

enum KICK_TYPE_ENUM {
	KICK_TYPE__AS_BAN,
	KICK_TYPE__IP_BAN,
	KICK_TYPE__BAD_COUNTRY,
	KICK_TYPE__PROXY_DETECTED,
	KICK_TYPE__AS_CHECK_FAIL,
	KICK_TYPE__PROXY_CHECK_FAIL,
	KICK_TYPE__COUNTRY_CHECK_FAIL,
    KICK_TYPE__SUPERVISOR
}

enum _:BG_PLAYER_DATA_STRUCT {
    BG_PDS__AS[MAX_AS_LEN], // AS number
    BG_PDS__DESC[MAX_DESC_LEN], // Provider description
    BG_PDS__CODE[MAX_CODE_LEN * 2], // Country code
    BG_PDS__COUNTRY[MAX_COUNTRY_LEN], // Country name
    BG_PDS__ACCESS_TYPE, // Allow/deny access reason as integer (any value from ALLOW_TYPE_ENUM or KICK_TYPE_ENUM)
    BG_PDS__ACCESS[MAX_ACCESS_LEN], // Allow/deny access reason as string
    BG_PDS__ACCESS_EXT[MAX_ACCESS_EXT_LEN], // Access external data
    BG_PDS__CHECK_FAIL_FLAGS, // Bitsum of triggered check fail flags (see 'BG_CHECK_FAIL_FLAGS')
    BG_PDS__SV_STATUS[MAX_SV_STATUS_LEN] // Supervisor status as string
}

/**
 * Called to request country name and country code for specified IP address.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer			Checking player index or 0 if this is call for any command
 * @param szIP					IP address to check
 * @param iMaxTries		    Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								        PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestGeoData(pPlayer, const szIP[], iMaxTries);

/**
 * Called to request AS number for specified IP address.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer			Checking player index or 0 if this is call for 'bg_get_as_by_ip' command
 * @param szIP					IP address to check
 * @param iMaxTries		Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								        PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestAsInfo(pPlayer, const szIP[], iMaxTries);

/**
 * Called to check specified IP address for Proxy/VPN.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer			Checking player index or 0 if this is call for 'bg_check_ip' command
 * @param szIP					IP address to check
 * @param iMaxTries		Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								        PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestProxyStatus(pPlayer, const szIP[], iMaxTries);

/**
 * Called to check specified player in Supervisor.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer			Checking player index
 * @param szAsNumber	Player AS number
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								        PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestSupervising(pPlayer, const szAsNumber[MAX_AS_LEN]);

/**
 * Called when checks chain is over, so player allowed to enter the server, or not.
 *
 * @note	This forward is not called for bots/hltv
 * @note	From now on you can use BypassGuard_GetPlayerData() native
 *
 * @param pPlayer			    Player index
 * @param bAllowConnect   Allow connect (true) or deny (false, so player will be kicked soon)
 * @param ePlayerData        Player data (see 'BG_PLAYER_DATA_STRUCT')
 *
 * @noreturn
 */
forward BypassGuard_PlayerCheckComplete(pPlayer, bool:bAllowConnect, const ePlayerData[BG_PLAYER_DATA_STRUCT]);

/**
 * [EXT ASN #2] Called by BypassGuard_RequestExtAsInfo() to request AS number for specified IP address.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param szIP					IP address to check
 * @param iRequestID       Request id from BypassGuard_RequestExtAsInfo()
 * @param iMaxTries		    Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								        PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_FwdToExtAsInfoProvider(const szIP[], iRequestID, iMaxTries);

/**
 * [EXT ASN #4] Announce AS number for specified IP, that was provided through BypassGuard_SendExtAsInfo().
 *
 * @note Reply always be async (in other frame) like SQL_ThreadQuery.
 *
 * @param szIP				        Checking IP
 * @param iRequestID           Request id from BypassGuard_RequestExtAsInfo()
 * @param szAsNumber		AS number (can be "N/A")
 * @param szDesc				    Provider description (can be "N/A")
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
forward BypassGuard_AnnounceExtAsInfo(const szIP[], iRequestID, const szAsNumber[MAX_AS_LEN], const szDesc[MAX_DESC_LEN], bool:bSuccess);

/**
 * Sends country code and country name to main plugin as reply to BypassGuard_RequestGeoData().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for any command
 *
 * @param pPlayer				Checking player index or 0 if this is answer for any command
 * @param szCode				Country code
 * @param szCountry			Country name
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendGeoData(pPlayer, const szCode[], const szCountry[], bool:bSuccess);

/**
 * Sends AS number to main plugin as reply to BypassGuard_RequestAsInfo().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for 'bg_get_as_by_ip'
 *
 * @param pPlayer				Checking player index or 0 if this is answer for 'bg_get_as_by_ip' command
 * @param szAsNumber		AS number
 * @param szDesc				    Provider description
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendAsInfo(pPlayer, const szAsNumber[], const szDesc[], bool:bSuccess);

/**
 * Sends proxy status to main plugin as reply to BypassGuard_RequestProxyStatus().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for 'bg_check_ip'
 *
 * @param pPlayer				Checking player index or 0 if this is answer for 'bg_check_ip' command
 * @param IsProxy				Proxy status (supposed to be false if bSuccess is false)
 * @param bSuccess				true if request was success, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendProxyStatus(pPlayer, bool:IsProxy, bool:bSuccess);

/**
 * Sends supervising result to main plugin as reply to BypassGuard_RequestSupervising().
 *
 * @param pPlayer			    Player index
 * @param bAllowConnect   Allow connect (true) or deny (false, so player will be kicked soon)
 * @param szStatus              Supervising status as string
 * @param bByWhitepass     true when player have whitepass, false otherwise
 * @param bStrictStatus       Restriction status (strict/non-strict), always false when result is taken from whitepass cache
 *
 * @noreturn
 */
native BypassGuard_SendSupervisingResult(pPlayer, bool:bAllowConnect, const szStatus[MAX_SV_STATUS_LEN], bool:bByWhitepass, bool:bStrictStatus);

/**
 * Logs specified text to error log.
 *
 * @param szText				Text to log
 *
 * @noreturn
 */
native BypassGuard_LogError(const szText[]);

/**
 * Returns plugin folder name.
 *
 * @param szBuffer				Buffer to store folder name
 * @param iMaxLen				Maximum length of the buffer (usually sizeof - 1)
 *
 * @noreturn
 */
native BypassGuard_GetPluginFolderName(szBuffer[], iMaxLen);

/**
 * Gets data for the specified player (see 'BG_PLAYER_DATA_STRUCT').
 *
 * @note	You can use this only after player passed through forward BypassGuard_PlayerCheckComplete()
 *
 * @param pPlayer			    Player index
 * @param ePlayerData		buffer to store player data
 *
 * @return						1 if player is ready and data was stored to buffer
 *								        0 if player is not ready, so data not stored
 *								        -1 if player is not connected
 */
native BypassGuard_GetPlayerData(pPlayer, ePlayerData[BG_PLAYER_DATA_STRUCT]);

/**
 * Returns if the player is checked.
 *
 * @param pPlayer			    Player index
 *
 * @return          true if player is checked, false otherwise
 */
native bool:BypassGuard_IsPlayerChecked(pPlayer);

/**
 * [EXT ASN #1] Used as a bridge to request ASN info through main plugin from any ASN data provider.
 *
 * @note	Calling this will call forward BypassGuard_FwdToExtAsInfoProvider().
 * @note Reply always be async (in other frame) like SQL_ThreadQuery.
 *
 * @param szIP				        IP without port	
 *
 * @return          -1 if IP is invalid; > 0 as request unique id
 */
native BypassGuard_RequestExtAsInfo(const szIP[]);

/**
 * [EXT ASN #3] Sends AS number to main plugin as reply to forward BypassGuard_FwdToExtAsInfoProvider().
 *
 * @note	Calling this will call forward BypassGuard_AnnounceExtAsInfo().
 *
 * @param szIP				        Checking IP
 * @param iRequestID           Request id from BypassGuard_RequestExtAsInfo()
 * @param szAsNumber		AS number (can be "N/A")
 * @param szDesc				    Provider description (can be "N/A")
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendExtAsInfo(const szIP[], iRequestID, const szAsNumber[], const szDesc[], bool:bSuccess);
