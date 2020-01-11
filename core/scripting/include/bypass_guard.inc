#define MAX_COUNTRY_LEN 64
#define MAX_CODE_LEN 3
#define MAX_AS_LEN 16
#define MAX_DESC_LEN 64
#define MAX_RESPONSE_LEN 256

/**
 * Called to request country name and country code for specified IP address.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param iUserID				Checking player pointer or 0 if this is call for any command
 * @param szIP					IP address to check
 * @param iMaxTries				Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestGeoData(pPlayer, szIP[], iMaxTries)

/**
 * Called to request AS number for specified IP address.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer				Checking player pointer or 0 if this is call for 'bg_get_as_by_ip' command
 * @param szIP					IP address to check
 * @param iMaxTries				Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestAsInfo(pPlayer, szIP[], iMaxTries)

/**
 * Called to check specified IP address for Proxy/VPN.
 *
 * @note	Plugin that handles request MUST return PLUGIN_HANDLED
 *
 * @param pPlayer				Checking player pointer or 0 if this is call for 'bg_check_ip' command
 * @param szIP					IP address to check
 * @param iMaxTries				Max check retry count (if check fails)
 *
 * @return						PLUGIN_HANDLED to handle request (agregate it)
 *								PLUGIN_CONTINUE to skip request (pass to other provider)
 */
forward BypassGuard_RequestProxyStatus(pPlayer, szIP[], iMaxTries)

/**
 * Sends country code and country name to main plugin as reply to BypassGuard_RequestGeoData().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for any command
 *
 * @param pPlayer				Checking player pointer or 0 if this is answer for any command
 * @param szCode				Country code
 * @param szCountry				Country name
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendGeoData(pPlayer, szCode[], szCountry[], bool:bSuccess)

/**
 * Sends AS number to main plugin as reply to BypassGuard_RequestAsInfo().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for 'bg_get_as_by_ip'
 *
 * @param pPlayer				Checking player pointer or 0 if this is answer for 'bg_get_as_by_ip' command
 * @param szAsNumber			AS number
 * @param szDesc				Provider description
 * @param bSuccess				true if request was successful, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendAsInfo(pPlayer, szAsNumber[], szDesc[], bool:bSuccess)

/**
 * Sends proxy status to main plugin as reply to BypassGuard_RequestProxyStatus().
 *
 * @note	Calling this with pPlayer = 0 suppose that this is instant cache-based answer for 'bg_check_ip'
 *
 * @param pPlayer				Checking player pointer or 0 if this is answer for 'bg_check_ip' command
 * @param IsProxy				Proxy status (supposed to be false if bSuccess is false)
 * @param bSuccess				true if request was success, false otherwise
 *
 * @noreturn
 */
native BypassGuard_SendProxyStatus(pPlayer, bool:IsProxy, bool:bSuccess)

/**
 * Logs specified text to error log.
 *
 * @param szText				Text to log
 *
 * @noreturn
 */
native BypassGuard_LogError(szText[])

/**
 * Returns plugin folder name.
 *
 * @param szBuffer				Buffer to store folder name
 * @param iMaxLen				Maximum length of the buffer (usually sizeof - 1)
 *
 * @noreturn
 */
native BypassGuard_GetPluginFolderName(szBuffer[], iMaxLen)