// Плагин для тестирования нового функционала ядра 1.1.14 (поддержка ожидаемого обновления AmxBans RBS (бан по ASN))

/* История обновлений:
	0.1 (11.10.2024):
		* Открытый релиз
*/

new const PLUGIN_VERSION[] = "0.1"

#include <amxmodx>
#include <bypass_guard>

new Trie:g_tRequests

public plugin_init() {
	register_plugin("[BG] EXT AS Info Test", PLUGIN_VERSION, "mx?!")
	
	g_tRequests = TrieCreate()
	
	register_srvcmd("bg_ext_as_info_test", "srvcmd_ExtAsInfoTest")
}

public srvcmd_ExtAsInfoTest() {
	if(read_argc() != 2) {
		server_print("* Usage: bg_ext_as_info_test <ip without port>")
		return PLUGIN_HANDLED
	}
	
	new szIP[MAX_IP_LENGTH]
	read_argv(1, szIP, charsmax(szIP))
	
	if(!IsIpValid(szIP)) {
		server_print("* Error! Wrong IP specified!")
		return PLUGIN_HANDLED
	}
	
	server_print("* Sending request for IP %s", szIP)
	new iRequestID = BypassGuard_RequestExtAsInfo(szIP)
	server_print("* Request for IP %s was sent with request id %i", szIP, iRequestID)

	if(iRequestID == -1) {
		server_print("* Main plugin reports that IP is invalid!")
		return PLUGIN_HANDLED
	}

	TrieSetCell(g_tRequests, fmt("%i", iRequestID), 0)
	
	return PLUGIN_HANDLED
}

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
public BypassGuard_AnnounceExtAsInfo(const szIP[], iRequestID, const szAsNumber[MAX_AS_LEN], const szDesc[MAX_DESC_LEN], bool:bSuccess) {
	//server_print("%s %i %s %s %i [%i]", szIP, iRequestID, szAsNumber, szDesc, bSuccess, TrieKeyExists(g_tRequests, fmt("%i", iRequestID)))
	
	if(!TrieKeyExists(g_tRequests, fmt("%i", iRequestID))) {
		return
	}
		
	TrieDeleteKey(g_tRequests, fmt("%i", iRequestID))
	
	server_print("* EXT AS info request id %i status: %s. ASN: %s, Desc: %s", iRequestID, bSuccess ? "success" : "fail", szAsNumber, szDesc)
}

bool:IsIpValid(szIP[]) {
	new i, szRight[MAX_IP_LENGTH], szPart[4], iCount

	strtok(szIP, szPart, charsmax(szPart), szRight, charsmax(szRight), '.')

	while(szPart[0] >= '0' && szPart[0] <= '9')	{
		i = str_to_num(szPart)

		if(i < 0 || i > 255) {
			return false
		}

		iCount++
		strtok(szRight, szPart, charsmax(szPart), szRight, charsmax(szRight), '.')
	}

	return (iCount == 4)
}
