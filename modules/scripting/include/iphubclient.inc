/*
* AMX Mod X
*	IPHub Client include.
*
* Author: the_hunter
* Version: 1.0.0
*
* MIT License
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#if defined _iphubclient_included
	#endinput
#endif
#define _iphubclient_included

#pragma reqlib iphubclient
#if !defined AMXMODX_NOAUTOLOAD
	#pragma loadlib iphubclient
#endif

enum _:IPHubData
{
	iphub_ip[16],
	iphub_code[4],
	iphub_name[32],
	iphub_asn,
	iphub_isp[64],
	iphub_block,
	iphub_error[256]
};

/**
 * Sends request to IPHub service https://iphub.info/api
 *
 * @param szIp			IP address to check.
 * @param szKey			IPHub API key.
 * @param attempts		Number of attempts to send request. Minimum value: 1; Maximum value 5.
 * @param delay			Delay between attempts in milliseconds. Minimum value: 500; Maximum value 5000.
 *
 * @return				The request ID to be used in other natives.
 */
native iphub_send_request(const szIp[], const szKey[], attempts = 3, delay = 1000);

/**
 * Gets the IP address associated with request.
 *
 * @param request		Request ID.
 * @param szIp			Destination string buffer.
 * @param maxLength		Maximum length of output string buffer.
 *
 * @return				Number of cells written.
 */
native iphub_request_ip(request, szIp[], maxLength);

/**
 * Gets the IPHub API key associated with request.
 *
 * @param request		Request ID.
 * @param szKey			Destination string buffer.
 * @param maxLength		Maximum length of output string buffer.
 *
 * @return				Number of cells written.
 */
native iphub_request_key(request, szKey[], maxLength);

/**
 * Gets the number of attempts to send request.
 *
 * @param request		Request ID.
 *
 * @return				Number of attempts.
 */
native iphub_request_attempts(request);

/**
 * Gets the delay between attempts in milliseconds.
 *
 * @param request		Request ID.
 *
 * @return				Delay between attempts.
 */
native iphub_request_delay(request);

/**
 * Gets plugin ID that initiated the request.
 *
 * @param request		Request ID.
 *
 * @return				Plugin ID.
 */
native iphub_request_initiator(request);

/**
 * It can be used in the iphub_response_received forward to check
 * whether the response needs to be handled.
 *
 * @param request		Request ID.
 *
 * @return				True, if the plugin that initiated the request
 *						is the one who calls this native; False otherwise.
 */
native bool:iphub_initiated_by_me(request);

/**
 * Called when request has been added to the queue.
 *
 * @param request		Request ID.
 */
forward iphub_request_queued(request);

/**
 * Called when request is executed.
 *
 * @param request		Request ID.
 */
forward iphub_request_in_progress(request);

/**
 * Called after response has been received.
 *
 * @param request		Request ID.
 * @param response		Response content.
 * @param response		Response status code.
 */
forward iphub_response_received(request, response[IPHubData], status);
