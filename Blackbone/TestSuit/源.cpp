#include <optional>
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <cassert>

#pragma comment(lib, "ntdll.lib")




// 声明模板类 _Vb_val
template <class T>
class _Vb_val {
public:
    _Vb_val() {
        // 构造函数
    }

    void display() const {
        std::cout << "This is _Vb_val template class with type: " << typeid(T).name() << std::endl;
    }
};

template <class _Ty, class _Alloc = std::allocator<_Ty>>
class vector {
private:
    // 使模板类 _Vb_val 成为友元类，允许 _Vb_val 访问 vector 的私有和保护成员
    template <class>
    friend class _Vb_val;

    _Ty _value; // 私有成员示例

public:
    vector(_Ty value) : _value(value) {}

    void showValue() const {
        std::cout << "Value in vector: " << _value << std::endl;
    }
};

template <typename T>
void printType() {
}


class ss
{
public:
    int x;
};

void CheckLoadDriverPrivilege(HANDLE hToken)
{
    DWORD dwSize = 0;
    PTOKEN_PRIVILEGES pPrivs = NULL;

    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    pPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);

    if(GetTokenInformation(hToken,TokenPrivileges,pPrivs,dwSize,&dwSize))
    {
	    for(DWORD i =0;i<pPrivs->PrivilegeCount;i++)
	    {
            LUID_AND_ATTRIBUTES la = pPrivs->Privileges[i];
            wchar_t szName[256];
            DWORD dwNameLen = sizeof(szName) / sizeof(szName[0]);

            if(LookupPrivilegeName(NULL,&la.Luid,szName,&dwNameLen))
            {

				printf("该进程拥有的权限：%ws\t",szName);
                if (la.Attributes & SE_PRIVILEGE_ENABLED) {
                    printf("Enabled\n");
                }
                else
                {
                    printf("disabled\n");
                }
                //la.Attributes & SE_PRIVILEGE_ENABLED

                //printf("la.Attributes:%d\n",la.Attributes);
                //printf("SE_PRIVILEGE_ENBALED:%d\n",SE_PRIVILEGE_ENABLED);

	            //if(wcscmp(szName,L"SeLoadDriverPrivilege") == 0)
	            //{
             //       printf("该进程具有加载驱动的权限。\n");
             //       free(pPrivs);
             //       return;
             //   }
             //   else
             //   {
             //       printf("权限：%ws\n",szName);
             //   }
            }
	    }

    }else {
        printf("无法获取令牌信息。错误: %lu\n", GetLastError());
    }

    if (pPrivs)
    {
		CloseHandle(pPrivs);
        free(pPrivs);
        pPrivs = NULL;
    }
}

std::optional<int> findValue(bool condition)
{
    if (condition)
    {
        return 42;
    }else
    {
        return std::nullopt;
    }
}


template <class _Base,class... _Types>
class MyClass
{
public:
    void print()
    {
        std::cout << "Base type: " << typeid(_Base).name() << std::endl;
        std::cout <<"Number of additional types:"<<sizeof...(_Types) <<std::endl;
    }
};


struct nullA;
template<class T>
class opt
{
public:
    bool has_value = false;
	opt(nullA):has_value(false)
	{
		
	}
};

struct nullA
{
	
};

nullA nA;



int* findValueWithPointer(bool condition)
{
	if(condition)
	{
        return new int(42);
	}
    else
    {
        return nullptr;
    }
}

//template<class T,class Y>
//class paramTwo
//{
//public:
//    paramTwo()
//    {
//        printf("paramTwo\n");
//    }
//};

template<typename T>
class paramTwo
{
public:
    paramTwo()
    {
        printf("paramOne\n");
    }
    paramTwo(T name)
    {
	    
    }
};


template<typename T>
class A
{
public:
    T name;
    A(T value):name(value){}
};

int main(){

    paramTwo  x1(10);
    A a(10);
    A w('c');
    A c(x1);



    paramTwo<nullA> pt;




    // It's  used to allocate the memory with pointer

    nullA t;

    std::optional<nullA>  x = t;
    std::optional<int> xint = 10;
    std::optional<paramTwo<nullA>> xParam = pt;


    return 1;


    opt<int> op = nA;

    if(op.has_value)
    {
        printf("has_value\n");
    }else
    {
        printf("No has value\n");
    }
	
    std::optional<int> result_data = std::nullopt;    // Returned value


    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    return 1;
    auto result = findValue(true);

    if(result.has_value())
    {
        std::cout << "Value found:" << result.value() << std::endl;
    }else
    {
        std::cout << "No value found." << std::endl;
    }

    return 1;



    HANDLE hToken = GetCurrentProcessToken();

    std::cout << hToken << std::endl;

    // Define a buffer to receive token information
    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLength);
    std::cout << "Error:" << GetLastError() << std::endl;
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token information size." << std::endl;
        return 1;
    }
    else
    {
        std::cout << "successful to get token information size." << std::endl;
    }

    auto tokenInfo = reinterpret_cast<PTOKEN_USER>(new BYTE[tokenInfoLength]);

    if(!GetTokenInformation(hToken,TokenUser,tokenInfo,tokenInfoLength,&tokenInfoLength))
    {
	    
    }



    return 1;

    HANDLE processHandle = GetCurrentProcess();
    HANDLE processTokenHandle;

    if(OpenProcessToken(processHandle, TOKEN_QUERY, &processTokenHandle))
    {
        printf("正常打开进程令牌\n");
        CheckLoadDriverPrivilege(processTokenHandle);
        if (processTokenHandle)
            CloseHandle(processTokenHandle);

    }else
    {
        printf("无法打开进程令牌。错误: %lu\n", GetLastError());
    }



    return 1;

    HANDLE handle = GetCurrentThread();
    HANDLE TokenHandle;

    printf("HANDLE:%d",handle);
    if(OpenThreadToken(GetCurrentThread(), STANDARD_RIGHTS_READ, TRUE, &TokenHandle))
    {
        printf("Successfully opened thread token.\n");
        CloseHandle(TokenHandle);

    }else
    {
        DWORD error = GetLastError();
        printf("Failed to open thread token. Error: %lu\n", error);
    }



    return 1;

    // OpenThreadToken;

	printType<int>();
    printType<char>();
    printType<ss>();

    return 1;
    vector<int> vec(100);
    vec.showValue();

    _Vb_val<int> vb;
    vb.display();

    return 1;

	ULONG bufferSize = 1024 * 1024; // 1 MB
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    MEMORY_BASIC_INFORMATION mbi;
    int queryResult = VirtualQuery(buffer, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    if(queryResult)
    {
        std::wcout << L"Base Address: " << mbi.BaseAddress << std::endl;
        std::wcout << L"Allocation Base: " << mbi.AllocationBase << std::endl;
        std::wcout << L"Region Size: " << mbi.RegionSize << std::endl;
        std::wcout << L"State: " << mbi.State << std::endl;  // MEM_COMMIT, MEM_RESERVE, etc.
        std::wcout << L"Protect: " << mbi.Protect << std::endl;  // PAGE_READWRITE, etc.
    }
    std::wcout << "_______________________________" << std::endl;

    if (!buffer)
    {
        std::cerr << "Failed to allocate buffer." << std::endl;
        return 1;
    }

    ULONG returnLength = 0;
    NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &returnLength);

    if (!NT_SUCCESS(status))
    {
        std::cerr << "NtQuerySystemInformation failed." << std::endl;
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    auto pInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer);

    while (true)
    {
        std::wcout << L"Process Name: " << (pInfo->ImageName.Buffer ? pInfo->ImageName.Buffer : L"System Idle Process")
            << L", PID: " << pInfo->UniqueProcessId << std::endl;

        if (pInfo->NextEntryOffset == 0)
            break;

        pInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}





