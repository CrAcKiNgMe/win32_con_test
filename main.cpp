

// Including SDKDDKVer.h defines the highest available Windows platform.

// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.

//#include <SDKDDKVer.h>

#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wlanapi.h>
#include <objbase.h>
#include <wtypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string>

#include <Wininet.h>

// Need to link with Wlanapi.lib and Ole32.lib
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

#pragma  comment(lib, "wininet.lib")
#include <winsock2.h>
#pragma message( "asdfasdfasdfa")
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <time.h>
// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
/* Note: could also use malloc() and free() */


void HttpRequest()
{
	//向http://192.168.8.72:8080/oss/client/analysis.g发送数据.   

	const char* lpURL = ("http://www.macvendorlookup.com/api/v2/00-23-AB-7B-58-99");   

	if (!::InternetCheckConnectionA(lpURL, FLAG_ICC_FORCE_CONNECTION, 0))  
	{

		return;   
	}

	HINTERNET hOpen = ::InternetOpenA(("windows"), INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY, NULL, NULL, 0);   
	if (NULL == hOpen) 
	{
		return;   
	}


	const char* lpDomainName = ("www.macvendorlookup.com"); // 注意不能带 http://   
	// 该函数第3个参数不能是80,而应该是8080   
	HINTERNET hConnect = ::InternetConnectA(hOpen, lpDomainName, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);   
	if (NULL == hConnect)   
	{
		goto FUN_END2;   
	}

	// 注意第3个参数的个数,最前面要有"/",它同lpURL拼接成http://192.168.8.72:8080/oss/client/analysis.g   
	const char* szAccept[] = {("*/*"), NULL}; 

	DWORD dwFlag = INTERNET_FLAG_NO_CACHE_WRITE;   
	HINTERNET hOpenRequest = ::HttpOpenRequestA(hConnect, NULL, ("/api/v2/00-23-AB-7B-58-99"), ("HTTP/1.1"), lpURL, szAccept, dwFlag, 0);   
	if (NULL == hOpenRequest)
	{
		goto FUN_END1;   
	}

	BOOL bRet;   

	// 外发的header.   
	// 注意,这里的头部很容易错.   
	// 每个字符串结尾不能带诸如 "/r/n","\r\n"这样的结尾,最后一个字符串必须要带两个"\r\n",也就是"\r\n\r\n".   
	// 有些网友写的示例中,每个字符串后都带有诸如 "/r/n"或"\r\n"这样的结尾,但在我的测试中发现是错误的,   
	// HttpQueryInfo返回的状态码总是400,意思是"错误请求 — 请求中有语法问题，或不能满足请求",估计这跟   
	// 具体的web服务有关.但有个简单的方式处理该问题,可使用chrome浏览器访问某个url(这里是http://192.168.8.72:8080/oss/client/// analysis.g),然后使用抓包工具Wireshark抓取http包,分析request和response头.然后再使用你的程序请求你的url,一样抓包,然后对// 比这两次抓取的数据包中http头有什么区别,修改你的代码,不断尝试,直到成功.   
	CHAR headerLanguage[] = ("Accept-Language: zh-CN,zh;q=0.8");   
	CHAR headerEncoding[] = ("Accept-Encoding: gzip,deflate,sdch");   
	CHAR headerCharset[] = ("Accept-Charset:utf-8;q=0.7,*;q=0.3");   
	CHAR headerContentType[] = ("Content-Type: text/xml");   
	CHAR headerHost[] = ("Host: 192.168.8.72:8080");   
	CHAR headerOrigin[] = ("Origin: http://192.168.8.72:8080");   
	CHAR headerEndFlag[64];   
	sprintf(headerEndFlag, ("\r\n\r\n")); //注意结尾有两个\r\n   

	// 添加header 信息   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerLanguage,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerEncoding,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerCharset,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerContentType, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerHost, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerOrigin, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerReferer, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   
	//bRet = HttpAddRequestHeadersA(hOpenRequest, headerEndFlag, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);   


	int iTimeout = 1000;  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_CONNECT_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_SEND_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_RECEIVE_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_DATA_SEND_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_DATA_RECEIVE_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  
	InternetSetOptionA(hOpenRequest, INTERNET_OPTION_LISTEN_TIMEOUT,  
		&iTimeout, sizeof(iTimeout));  


	bRet = ::HttpSendRequestA(hOpenRequest, NULL, 0, NULL, 0);   
	DWORD dwErr = ::GetLastError();   
	if (!bRet)  
	{
		goto FUN_END1;   
	}

	CHAR szBuff[1024] = {0};   
	DWORD dwBuffSize = 1024;   

	bRet = ::HttpQueryInfoA(hOpenRequest, HTTP_QUERY_STATUS_CODE, (LPVOID)szBuff, &dwBuffSize, NULL);   

	//Reference to http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html   
	int nStatusCode = atoi(szBuff);   
	if (nStatusCode<200 || 206<nStatusCode) 
	{
		bRet = FALSE;   
	}

	if (bRet)   
	{   
		CHAR szBuff[1024] = {0};   
		DWORD dwBuffSize = 1024;  
		bRet = ::HttpQueryInfoA(hOpenRequest, HTTP_QUERY_CONTENT_LENGTH, (LPVOID)szBuff, &dwBuffSize, NULL);   

		dwBuffSize = 1024;  

		bRet = ::InternetReadFile(hOpenRequest, szBuff, dwBuffSize, &dwBuffSize) ;
		//bRet = ::InternetReadFile(hOpenRequest, szBuff, dwBuffSize, &dwBuffSize) ;
		
		printf("szBuff %s", szBuff);

		if (bRet)   
		{   
			// ...   
		}   
	}   
	InternetCloseHandle(hOpenRequest);

FUN_END1:   
	::InternetCloseHandle(hConnect);   

FUN_END2:   
	::InternetCloseHandle(hOpen);
}


namespace std
{
	typedef basic_string<TCHAR, char_traits<TCHAR>, allocator<TCHAR> >
		tstring;
} 
using  namespace std;

int tmp();

class CWLAN
{
public:
	enum
	{
		except_open_wlan_failed,
		except_invalid_client_handle,
		except_enum_interfaces,
		except_no_interface_connected,
		except_no_available_network,
		except_no_wlannetwork_connected



	};

private:
	HANDLE m_hClient;
	DWORD  m_dwVersion;
	DWORD  m_dwMaxClient;
public:
	CWLAN()
	{ 
		m_hClient		= NULL;
		m_dwMaxClient	= 2;
		m_dwVersion		= 0;

	}
	~CWLAN()
	{

	}

public:
	int Init()
	{
		DWORD	dwResult = WlanOpenHandle(m_dwMaxClient, NULL, &m_dwVersion, &m_hClient);

		if (dwResult != ERROR_SUCCESS) 
		{
			wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
			return except_open_wlan_failed;
			// You can use FormatMessage here to find out why the function failed
		}

		return 0;

	}
	int GetCurrentWlanInterface(GUID & guid)
	{
		if (m_hClient == NULL)
		{
			return  except_invalid_client_handle;
		}

		DWORD						dwRetVal = 0;
		int							iRet	= 0;
		PWLAN_INTERFACE_INFO_LIST	pIfList = NULL;
		PWLAN_INTERFACE_INFO		pIfInfo = NULL;

		DWORD dwResult  = WlanEnumInterfaces(m_hClient, NULL, &pIfList);

		if (dwResult != ERROR_SUCCESS) 
		{
			wprintf(L"WlanOpenHandle failed with error: %u\n", dwResult);
			return except_enum_interfaces;
			// You can use FormatMessage here to find out why the function failed
		}

		wprintf(L"Num Entries: %lu\n", pIfList->dwNumberOfItems);
		wprintf(L"Current Index: %lu\n", pIfList->dwIndex);



		for (int i = 0; i < (int)pIfList->dwNumberOfItems; i++) 
		{

			pIfInfo = (WLAN_INTERFACE_INFO *)&pIfList->InterfaceInfo[i];
			wprintf(L"  Interface Index[%u]:\t %lu\n", i, i);




			wprintf(L"\n");

			switch (pIfInfo->isState) 
			{

			case wlan_interface_state_connected:
				{
					wprintf(L"Connected\n");
					guid = pIfInfo->InterfaceGuid;
					if (pIfList != NULL) 
					{
						WlanFreeMemory(pIfList);
						pIfList = NULL;
					}
				}
				return 0;
			case wlan_interface_state_not_ready:
			case wlan_interface_state_ad_hoc_network_formed:
			case wlan_interface_state_disconnecting:
			case wlan_interface_state_disconnected:
			case wlan_interface_state_associating:
			case wlan_interface_state_discovering:
			case wlan_interface_state_authenticating:
			default:
				break;
			}

		}

final:

		if (pIfList != NULL) {
			WlanFreeMemory(pIfList);
			pIfList = NULL;
		}


		return  except_no_interface_connected;


	}

	int GetCurrentConnectSSID(const GUID& interfaceguid, string& ssid)
	{

		if (m_hClient == NULL)
		{
			return except_invalid_client_handle;
		}


		PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
		PWLAN_AVAILABLE_NETWORK pBssEntry = NULL;

		DWORD    dwResult = WlanGetAvailableNetworkList(m_hClient,
			&interfaceguid,
			0,
			NULL,
			&pBssList);


		if (dwResult != ERROR_SUCCESS) {
			wprintf(L"WlanGetAvailableNetworkList failed with error: %u\n",
				dwResult);

			return except_no_available_network;
			// You can use FormatMessage to find out why the function failed
		}

		int iRSSI = 0;

		wprintf(L"WLAN_AVAILABLE_NETWORK_LIST for this interface\n");

		wprintf(L"  Num Entries: %lu\n\n", pBssList->dwNumberOfItems);

		int nConnectedFlag = 0;

		for (int j = 0; j < pBssList->dwNumberOfItems; j++)
		{





			pBssEntry =
				(WLAN_AVAILABLE_NETWORK *)& pBssList->Network[j];


			if ((pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) == 0)
			{
				continue;
			}

			nConnectedFlag = 1;

			//wprintf(L"  Profile Name[%u]:  %ws\n", j, pBssEntry->strProfileName);


			if (pBssEntry->dot11Ssid.uSSIDLength == 0)
			{
				ssid = "";
			}

			else 
			{
				for (int k = 0; k < pBssEntry->dot11Ssid.uSSIDLength; k++) 
				{
					ssid.append(1, pBssEntry->dot11Ssid.ucSSID[k]);

				}



				//wprintf(L"\n");
			}

			//wprintf(L"  BSS Network type[%u]:\t ", j);
			switch (pBssEntry->dot11BssType) {
			case dot11_BSS_type_infrastructure:
				//wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
				break;
			case dot11_BSS_type_independent:
				//wprintf(L"Infrastructure (%u)\n", pBssEntry->dot11BssType);
				break;
			default:
				//wprintf(L"Other (%lu)\n", pBssEntry->dot11BssType);
				break;
			}

			//wprintf(L"  Number of BSSIDs[%u]:\t %u\n", j, pBssEntry->uNumberOfBssids);

			//wprintf(L"  Connectable[%u]:\t ", j);
			if (pBssEntry->bNetworkConnectable)
			{
				//wprintf(L"Yes\n");
			}
			else 
			{
				//wprintf(L"No\n");
				//wprintf(L"  Not connectable WLAN_REASON_CODE value[%u]:\t %u\n", j,pBssEntry->wlanNotConnectableReason);
			}

			//wprintf(L"  Number of PHY types supported[%u]:\t %u\n", j, pBssEntry->uNumberOfPhyTypes);

			if (pBssEntry->wlanSignalQuality == 0)
			{
				iRSSI = -100;
			}
			else if (pBssEntry->wlanSignalQuality == 100)
			{
				iRSSI = -50;
			}
			else
			{
				iRSSI = -100 + (pBssEntry->wlanSignalQuality / 2);
			}

			//wprintf(L"  Signal Quality[%u]:\t %u (RSSI: %i dBm)\n", j,pBssEntry->wlanSignalQuality, iRSSI);

			//wprintf(L"  Security Enabled[%u]:\t ", j);
			if (pBssEntry->bSecurityEnabled)
			{
				//wprintf(L"Yes\n");
			}
			else
			{
				//wprintf(L"No\n");
			}

			//wprintf(L"  Default AuthAlgorithm[%u]: ", j);
			switch (pBssEntry->dot11DefaultAuthAlgorithm) {
			case DOT11_AUTH_ALGO_80211_OPEN:
				//wprintf(L"802.11 Open (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_80211_SHARED_KEY:
				//wprintf(L"802.11 Shared (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_WPA:
				//wprintf(L"WPA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_WPA_PSK:
				//wprintf(L"WPA-PSK (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_WPA_NONE:
				//wprintf(L"WPA-None (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_RSNA:
				//wprintf(L"RSNA (%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			case DOT11_AUTH_ALGO_RSNA_PSK:
				//wprintf(L"RSNA with PSK(%u)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			default:
				//wprintf(L"Other (%lu)\n", pBssEntry->dot11DefaultAuthAlgorithm);
				break;
			}

			//wprintf(L"  Default CipherAlgorithm[%u]: ", j);
			switch (pBssEntry->dot11DefaultCipherAlgorithm) {
			case DOT11_CIPHER_ALGO_NONE:
				//wprintf(L"None (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			case DOT11_CIPHER_ALGO_WEP40:
				//wprintf(L"WEP-40 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			case DOT11_CIPHER_ALGO_TKIP:
				//wprintf(L"TKIP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			case DOT11_CIPHER_ALGO_CCMP:
				//wprintf(L"CCMP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			case DOT11_CIPHER_ALGO_WEP104:
				//wprintf(L"WEP-104 (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			case DOT11_CIPHER_ALGO_WEP:
				//wprintf(L"WEP (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			default:
				//wprintf(L"Other (0x%x)\n", pBssEntry->dot11DefaultCipherAlgorithm);
				break;
			}

			//wprintf(L"  Flags[%u]:\t 0x%x", j, pBssEntry->dwFlags);

			if (pBssEntry->dwFlags & WLAN_AVAILABLE_NETWORK_HAS_PROFILE)
			{
				//wprintf(L" - Has profile");
			}

			//wprintf(L"\n");


		}


		if (pBssList != NULL) {
			WlanFreeMemory(pBssList);
			pBssList = NULL;
		}

		if(nConnectedFlag)
		{
			return 0;
		}


		return except_no_wlannetwork_connected;
	}

	int GetCurrentGateWay(const string& guid, string& gateway)
	{
		PIP_ADAPTER_INFO pAdapterInfo;
		PIP_ADAPTER_INFO pAdapter = NULL;
		DWORD dwRetVal = 0;
		UINT i;

		/* variables used to print DHCP time info */
		struct tm newtime;
		char buffer[32];
		errno_t error;

		ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
		pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(sizeof (IP_ADAPTER_INFO));
		if (pAdapterInfo == NULL) {
			//printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
		// Make an initial call to GetAdaptersInfo to get
		// the necessary size into the ulOutBufLen variable
		if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
		{
			FREE(pAdapterInfo);
			pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(ulOutBufLen);
			if (pAdapterInfo == NULL) 
			{
				//printf("Error allocating memory needed to call GetAdaptersinfo\n");
				return 1;
			}
		}

		if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
		{
			pAdapter = pAdapterInfo;
			while (pAdapter) 
			{


				string strGUID;
				strGUID.assign(pAdapter->AdapterName);

				if(strGUID != guid)
				{
					//pAdapter = pAdapter->Next;
					//continue;
				}

				printf("\n\tComboIndex: \t%d\n", pAdapter->ComboIndex);
				printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);


				printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
				printf("\tAdapter Addr: \t");
				for (i = 0; i < pAdapter->AddressLength; i++) {
					if (i == (pAdapter->AddressLength - 1))
						printf("%.2X\n", (int) pAdapter->Address[i]);
					else
						printf("%.2X-", (int) pAdapter->Address[i]);
				}

				gateway.assign(pAdapter->GatewayList.IpAddress.String);


				break;
				//pAdapter = pAdapter->Next;
				//continue;

				//printf("\t***\n");


				//printf("\n");
			}
		} 

		else 
		{
			printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

		}
		if (pAdapterInfo)
		{
			FREE(pAdapterInfo);
		}

		return 0;

	}


};


int main()
{
	//tmp();

	CWLAN wlan;
	wlan.Init();
	GUID tmp;
	wstring wstrGUID;
	string ssid;
	WCHAR						GuidString[39] = { 0 };

	HttpRequest();


	int   nWlanFlag = 0;

	if( wlan.GetCurrentWlanInterface(tmp) == 0)
	{

		nWlanFlag = 1;

		int iRet = StringFromGUID2(tmp, (LPOLESTR)&GuidString,
			sizeof(GuidString) / sizeof(*GuidString));

		if (iRet == 0)
		{
			//wprintf(L"StringFromGUID2 failed\n");
		}

		wstrGUID.assign(GuidString);


		wprintf(L"guid %s", wstrGUID.c_str());

		if( wlan.GetCurrentConnectSSID(tmp, ssid) == 0)
		{

			printf("ssid %s", ssid.c_str());
		}

		string strGUID = "{646ACA29-B0A9-448B-8A5C-2FF2044D9AFF}";
		string strGateway;
		wlan.GetCurrentGateWay(strGUID, strGateway);
		//printf("gateway %s\n", strGateway.c_str());

	}


	else
	{
		printf("no wlan");
	}



	return 0;
}

int tmp()
{
	/* Some general variables */
	ULONG ulOutBufLen;
	DWORD dwRetVal;
	unsigned int i;

	/* variables used for GetNetworkParams */
	FIXED_INFO *pFixedInfo;
	IP_ADDR_STRING *pIPAddr;

	/* variables used for GetAdapterInfo */
	IP_ADAPTER_INFO *pAdapterInfo;
	IP_ADAPTER_INFO *pAdapter;

	/* variables used to print DHCP time info */
	struct tm newtime;
	char buffer[32];
	errno_t error;

	/* variables used for GetInterfaceInfo */
	IP_INTERFACE_INFO *pInterfaceInfo;

	/* variables used for GetIpAddrTable */
	MIB_IPADDRTABLE *pIPAddrTable;
	DWORD dwSize;
	IN_ADDR IPAddr;
	char *strIPAddr;

	/* variables used for AddIpAddress */
	UINT iaIPAddress;
	UINT imIPMask;
	ULONG NTEContext;
	ULONG NTEInstance;

	/* variables used for GetIpStatistics */
	MIB_IPSTATS *pStats;

	/* variables used for GetTcpStatistics */
	MIB_TCPSTATS *pTCPStats;

	printf("------------------------\n");
	printf("This is GetNetworkParams\n");
	printf("------------------------\n");

	pFixedInfo = (FIXED_INFO *) MALLOC(sizeof (FIXED_INFO));
	if (pFixedInfo == NULL) {
		printf("Error allocating memory needed to call GetNetworkParams\n");
		return 1;
	}
	ulOutBufLen = sizeof (FIXED_INFO);

	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO *) MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL) {
			printf("Error allocating memory needed to call GetNetworkParams\n");
			return 1;
		}
	}

	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
		printf("GetNetworkParams failed with error %d\n", dwRetVal);
		if (pFixedInfo)
			FREE(pFixedInfo);
		return 1;
	} else {
		printf("\tHost Name: %s\n", pFixedInfo->HostName);
		printf("\tDomain Name: %s\n", pFixedInfo->DomainName);
		printf("\tDNS Servers:\n");
		printf("\t\t%s\n", pFixedInfo->DnsServerList.IpAddress.String);

		pIPAddr = pFixedInfo->DnsServerList.Next;
		while (pIPAddr) {
			printf("\t\t%s\n", pIPAddr->IpAddress.String);
			pIPAddr = pIPAddr->Next;
		}

		printf("\tNode Type: ");
		switch (pFixedInfo->NodeType) {
		case 1:
			printf("%s\n", "Broadcast");
			break;
		case 2:
			printf("%s\n", "Peer to peer");
			break;
		case 4:
			printf("%s\n", "Mixed");
			break;
		case 8:
			printf("%s\n", "Hybrid");
			break;
		default:
			printf("\n");
		}

		printf("\tNetBIOS Scope ID: %s\n", pFixedInfo->ScopeId);

		if (pFixedInfo->EnableRouting)
			printf("\tIP Routing Enabled: Yes\n");
		else
			printf("\tIP Routing Enabled: No\n");

		if (pFixedInfo->EnableProxy)
			printf("\tWINS Proxy Enabled: Yes\n");
		else
			printf("\tWINS Proxy Enabled: No\n");

		if (pFixedInfo->EnableDns)
			printf("\tNetBIOS Resolution Uses DNS: Yes\n");
		else
			printf("\tNetBIOS Resolution Uses DNS: No\n");
	}

	/* Free allocated memory no longer needed */
	if (pFixedInfo) {
		FREE(pFixedInfo);
		pFixedInfo = NULL;
	}

	printf("------------------------\n");
	printf("This is GetAdaptersInfo\n");
	printf("------------------------\n");

	pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(sizeof (IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdapterInfo\n");
		return 1;
	}
	ulOutBufLen = sizeof (IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdapterInfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != NO_ERROR) {
		printf("GetAdaptersInfo failed with error %d\n", dwRetVal);
		if (pAdapterInfo)
			FREE(pAdapterInfo);
		return 1;
	}

	pAdapter = pAdapterInfo;
	while (pAdapter) {
		printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
		printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
		printf("\tAdapter Addr: \t");
		for (i = 0; i < (int) pAdapter->AddressLength; i++) {
			if (i == (pAdapter->AddressLength - 1))
				printf("%.2X\n", (int) pAdapter->Address[i]);
			else
				printf("%.2X-", (int) pAdapter->Address[i]);
		}
		printf("\tIP Address: \t%s\n",
			pAdapter->IpAddressList.IpAddress.String);
		printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

		printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
		printf("\t***\n");

		if (pAdapter->DhcpEnabled) {
			printf("\tDHCP Enabled: \tYes\n");
			printf("\tDHCP Server: \t%s\n",
				pAdapter->DhcpServer.IpAddress.String);

			printf("\tLease Obtained: ");
			/* Display local time */
			error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseObtained);
			if (error)
				printf("\tInvalid Argument to _localtime32_s\n");

			else {
				// Convert to an ASCII representation 
				error = asctime_s(buffer, 32, &newtime);
				if (error)
					printf("Invalid Argument to asctime_s\n");
				else
					/* asctime_s returns the string terminated by \n\0 */
					printf("%s", buffer);
			}

			printf("\tLease Expires:  ");
			error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseExpires);
			if (error)
				printf("Invalid Argument to _localtime32_s\n");
			else {
				// Convert to an ASCII representation 
				error = asctime_s(buffer, 32, &newtime);
				if (error)
					printf("Invalid Argument to asctime_s\n");
				else
					/* asctime_s returns the string terminated by \n\0 */
					printf("%s", buffer);
			}
		} else
			printf("\tDHCP Enabled: \tNo\n");

		if (pAdapter->HaveWins) {
			printf("\tHave Wins: \tYes\n");
			printf("\tPrimary Wins Server: \t%s\n",
				pAdapter->PrimaryWinsServer.IpAddress.String);
			printf("\tSecondary Wins Server: \t%s\n",
				pAdapter->SecondaryWinsServer.IpAddress.String);
		} else
			printf("\tHave Wins: \tNo\n");

		printf("\n");
		pAdapter = pAdapter->Next;
	}

	printf("------------------------\n");
	printf("This is GetInterfaceInfo\n");
	printf("------------------------\n");

	pInterfaceInfo = (IP_INTERFACE_INFO *) MALLOC(sizeof (IP_INTERFACE_INFO));
	if (pInterfaceInfo == NULL) {
		printf("Error allocating memory needed to call GetInterfaceInfo\n");
		return 1;
	}
	ulOutBufLen = sizeof (IP_INTERFACE_INFO);
	if (GetInterfaceInfo(pInterfaceInfo, &ulOutBufLen) ==
		ERROR_INSUFFICIENT_BUFFER) {
			FREE(pInterfaceInfo);
			pInterfaceInfo = (IP_INTERFACE_INFO *) MALLOC(ulOutBufLen);
			if (pInterfaceInfo == NULL) {
				printf("Error allocating memory needed to call GetInterfaceInfo\n");
				return 1;
			}
			printf("\t The size needed for the output buffer ulLen = %ld\n",
				ulOutBufLen);
	}

	if ((dwRetVal = GetInterfaceInfo(pInterfaceInfo, &ulOutBufLen)) == NO_ERROR) {
		printf("\tNum Adapters: %ld\n\n", pInterfaceInfo->NumAdapters);
		for (i = 0; i < (unsigned int) pInterfaceInfo->NumAdapters; i++) {
			printf("\tAdapter Index[%d]: %ld\n", i,
				pInterfaceInfo->Adapter[i].Index);
			printf("\tAdapter Name[%d]:  %ws\n\n", i,
				pInterfaceInfo->Adapter[i].Name);
		}
		printf("GetInterfaceInfo call succeeded.\n");
	} else {
		LPVOID lpMsgBuf = NULL;

		if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),       // Default language
			(LPTSTR) & lpMsgBuf, 0, NULL)) {
				printf("\tError: %s", lpMsgBuf);
		}
		LocalFree(lpMsgBuf);
	}

	/* If DHCP enabled, release and renew the IP address */
	/* THIS WORKS BUT IT TAKES A LONG TIME AND INTERRUPTS NET CONNECTIONS */
	if (pAdapterInfo->DhcpEnabled && pInterfaceInfo->NumAdapters) {
		printf("Calling IpReleaseAddress for Adapter[%d]\n", 0);
		if ((dwRetVal =
			IpReleaseAddress(&pInterfaceInfo->Adapter[0])) == NO_ERROR) {
				printf("Ip Release succeeded.\n");
		}
		if ((dwRetVal =
			IpRenewAddress(&pInterfaceInfo->Adapter[0])) == NO_ERROR) {
				printf("Ip Renew succeeded.\n");
		}
	}

	/* Free allocated memory no longer needed */
	if (pAdapterInfo) {
		FREE(pAdapterInfo);
		pAdapterInfo = NULL;
	}
	if (pInterfaceInfo) {
		FREE(pInterfaceInfo);
		pInterfaceInfo = NULL;
	}

	printf("----------------------\n");
	printf("This is GetIpAddrTable\n");
	printf("----------------------\n");

	pIPAddrTable = (MIB_IPADDRTABLE *) MALLOC(sizeof (MIB_IPADDRTABLE));
	if (pIPAddrTable == NULL) {
		printf("Error allocating memory needed to call GetIpAddrTable\n");
		return 1;
	}
	dwSize = 0;
	IPAddr.S_un.S_addr = ntohl(pIPAddrTable->table[1].dwAddr);
	strIPAddr = inet_ntoa(IPAddr);

	if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pIPAddrTable);
		pIPAddrTable = (MIB_IPADDRTABLE *) MALLOC(dwSize);
		if (pIPAddrTable == NULL) {
			printf("Error allocating memory needed to call GetIpAddrTable\n");
			return 1;
		}
	}

	if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
		printf("GetIpAddrTable failed with error %d\n", dwRetVal);
		if (pIPAddrTable)
			FREE(pIPAddrTable);
		return 1;
	}

	printf("\tNum Entries: %ld\n", pIPAddrTable->dwNumEntries);
	for (i = 0; i < (unsigned int) pIPAddrTable->dwNumEntries; i++) {
		printf("\n\tInterface Index[%d]:\t%ld\n", i,
			pIPAddrTable->table[i].dwIndex);
		IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwAddr;
		printf("\tIP Address[%d]:     \t%s\n", i, inet_ntoa(IPAddr));
		IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwMask;
		printf("\tSubnet Mask[%d]:    \t%s\n", i, inet_ntoa(IPAddr));
		IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwBCastAddr;
		printf("\tBroadCast[%d]:      \t%s (%ld%)\n", i, inet_ntoa(IPAddr),
			pIPAddrTable->table[i].dwBCastAddr);
		printf("\tReassembly size[%d]:\t%ld\n", i,
			pIPAddrTable->table[i].dwReasmSize);
		printf("\tAddress Index[%d]:  \t%ld\n", i,
			pIPAddrTable->table[i].dwIndex);
		printf("\tType and State[%d]:", i);
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_PRIMARY)
			printf("\tPrimary IP Address");
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DYNAMIC)
			printf("\tDynamic IP Address");
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DISCONNECTED)
			printf("\tAddress is on disconnected interface");
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_DELETED)
			printf("\tAddress is being deleted");
		if (pIPAddrTable->table[i].wType & MIB_IPADDR_TRANSIENT)
			printf("\tTransient address");
		printf("\n");
	}

	iaIPAddress = inet_addr("192.168.0.27");
	imIPMask = inet_addr("255.255.255.0");

	NTEContext = 0;
	NTEInstance = 0;

	if ((dwRetVal = AddIPAddress(iaIPAddress,
		imIPMask,
		pIPAddrTable->table[0].
		dwIndex,
		&NTEContext, &NTEInstance)) != NO_ERROR) {

			LPVOID lpMsgBuf;
			printf("\tError adding IP address.\n");

			if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),       // Default language
				(LPTSTR) & lpMsgBuf, 0, NULL)) {
					printf("\tError: %s", lpMsgBuf);
			}
			LocalFree(lpMsgBuf);
	}

	if ((dwRetVal = DeleteIPAddress(NTEContext)) != NO_ERROR) {
		printf("DeleteIPAddress failed with error %d\n", dwRetVal);
	}

	/* Free allocated memory no longer needed */
	if (pIPAddrTable) {
		FREE(pIPAddrTable);
		pIPAddrTable = NULL;
	}

	printf("-------------------------\n");
	printf("This is GetIPStatistics()\n");
	printf("-------------------------\n");

	pStats = (MIB_IPSTATS *) MALLOC(sizeof (MIB_IPSTATS));
	if (pStats == NULL) {
		printf("Error allocating memory needed to call GetIpStatistics\n");
		return 1;
	}

	if ((dwRetVal = GetIpStatistics(pStats)) != NO_ERROR) {
		printf("GetIPStatistics failed with error %d\n", dwRetVal);
		if (pStats)
			FREE(pStats);
		return 1;
	}

	printf("\tNumber of IP addresses: %ld\n", pStats->dwNumAddr);
	printf("\tNumber of Interfaces: %ld\n", pStats->dwNumIf);
	printf("\tReceives: %ld\n", pStats->dwInReceives);
	printf("\tOut Requests: %ld\n", pStats->dwOutRequests);
	printf("\tRoutes: %ld\n", pStats->dwNumRoutes);
	printf("\tTimeout Time: %ld\n", pStats->dwReasmTimeout);
	printf("\tIn Delivers: %ld\n", pStats->dwInDelivers);
	printf("\tIn Discards: %ld\n", pStats->dwInDiscards);
	printf("\tTotal In: %ld\n", pStats->dwInDelivers + pStats->dwInDiscards);
	printf("\tIn Header Errors: %ld\n", pStats->dwInHdrErrors);

	/* Free allocated memory no longer needed */
	if (pStats) {
		FREE(pStats);
		pStats = NULL;
	}

	printf("-------------------------\n");
	printf("This is GetTCPStatistics()\n");
	printf("-------------------------\n");

	pTCPStats = (MIB_TCPSTATS *) MALLOC(sizeof (MIB_TCPSTATS));
	if (pTCPStats == NULL) {
		printf("Error allocating memory needed to call GetTcpStatistics\n");
		return 1;
	}

	if ((dwRetVal = GetTcpStatistics(pTCPStats)) != NO_ERROR) {
		printf("GetTcpStatistics failed with error %d\n", dwRetVal);
		if (pTCPStats)
			FREE(pTCPStats);
		return 1;
	}

	printf("\tActive Opens: %ld\n", pTCPStats->dwActiveOpens);
	printf("\tPassive Opens: %ld\n", pTCPStats->dwPassiveOpens);
	printf("\tSegments Recv: %ld\n", pTCPStats->dwInSegs);
	printf("\tSegments Xmit: %ld\n", pTCPStats->dwOutSegs);
	printf("\tTotal # Conxs: %ld\n", pTCPStats->dwNumConns);

	/* Free allocated memory no longer needed */
	if (pTCPStats) {
		FREE(pTCPStats);
		pTCPStats = NULL;
	}

	return 0;
}
