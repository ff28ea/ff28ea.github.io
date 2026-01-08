
# sub_FFFFF8060C08F880 日志记录
## 储存
```c++
char *__fastcall sub_FFFFF8060C082F32(
        PCUNICODE_STRING SourceString,
        unsigned int a2,
        char *a3,
        const UNICODE_STRING *a4)
{
  __int16 v4; // bp
  const UNICODE_STRING *v9; // r15
  char v10; // di
  __int64 v13; // rdx
  __int64 v14; // r9
  _DWORD *v15; // rbx
  __int64 v16; // rcx
  __int64 v17; // r8
  PCUNICODE_STRING v21; // [rsp-38h] [rbp-38h] BYREF
  unsigned __int64 v22; // [rsp-30h] [rbp-30h]
  __int64 v23; // [rsp-28h] [rbp-28h]

  _BitScanForward(&_R13, v4 & 0xD20E);
  v23 = _R15;
  __asm { rcl     r13w, 0A1h }
  LOBYTE(_R15) = _R15 + 1;
  __asm { rcr     r15w, cl }
  v21 = SourceString;
  v9 = SourceString;
  v22 = a2;
  v10 = 0;
  _R12 = a4;
  if ( (unsigned __int8)sub_FFFFF8060BC1E7E0(&stru_FFFFF8060BE044B0, &v21) )
  {
    v15 = &dword_FFFFF8060BC394A0[470 * HIDWORD(v22)];
  }
  else
  {
    v16 = (unsigned int)dword_FFFFF8060BE04464;
    if ( dword_FFFFF8060BE04468 )
    {
      v13 = (dword_FFFFF8060BE04464 + 1) / 0x3E8u;
      v16 = (dword_FFFFF8060BE04464 + 1) % 0x3E8u;
      dword_FFFFF8060BE04464 = (dword_FFFFF8060BE04464 + 1) % 0x3E8u;
    }
    if ( (_DWORD)v16 == dword_FFFFF8060BE04460 && dword_FFFFF8060BE04468 )
    {
      v21 = (PCUNICODE_STRING)&dword_FFFFF8060BC394A0[470 * dword_FFFFF8060BE04460 + 262];
      LODWORD(v22) = dword_FFFFF8060BC394A0[470 * dword_FFFFF8060BE04460 + 334];
      sub_FFFFF8060BC1E788(&stru_FFFFF8060BE044B0, &v21);
      v13 = (dword_FFFFF8060BE04460 + 1) / 0x3E8u;
      dword_FFFFF8060BE04460 = (dword_FFFFF8060BE04460 + 1) % 0x3E8u;
      v16 = (unsigned int)dword_FFFFF8060BE04464;
    }
    else
    {
      v17 = (unsigned int)++dword_FFFFF8060BE04468;
    }
    v15 = &dword_FFFFF8060BC394A0[470 * (unsigned int)v16];
    *((_QWORD *)v15 + 132) = v15 + 2;
    *((_WORD *)v15 + 524) = 0;
    *((_WORD *)v15 + 525) = 520;
    v15[335] = sub_FFFFF8060BC1BBF0(v16, v13, v17, v14, v21, v22, v23);
    RtlCopyUnicodeString((PUNICODE_STRING)(v15 + 262), v9);
    if ( _R12 )
    {
      *((_WORD *)v15 + 673) = 520;
      *((_QWORD *)v15 + 169) = v15 + 340;
      *((_WORD *)v15 + 672) = 0;
      RtlCopyUnicodeString((PUNICODE_STRING)v15 + 84, _R12);
    }
    *(_QWORD *)v15 = 0LL;
    v15[334] = a2;
    sub_FFFFF8060BC316C0(v15 + 132, 0LL, 520LL);
    sub_FFFFF8060BC316C0(v15 + 266, 0LL, 272LL);
    v21 = (PCUNICODE_STRING)(v15 + 262);
    v22 = __PAIR64__(dword_FFFFF8060BE04464, a2);
    sub_FFFFF8060BC1E6A0(&stru_FFFFF8060BE044B0, &v21);
    v10 = 1;
    __asm { rcr     r12b, cl }
  }
  *a3 = v10;
  return (char *)v15;
}
```

## 提取&清理
```c++
__int64 __fastcall sub_FFFFF8060C080D2C(char *_RCX)
{
  char *v2; // rdi
  __int64 result; // rax
  __int64 v4; // rbx
  int v6; // edi
  __int128 v8; // [rsp+20h] [rbp-18h] BYREF

  v2 = _RCX;
  if ( dword_FFFFF8060BE04468 )
  {
    KeAcquireGuardedMutex(&Mutex);
    v4 = 1880LL * (unsigned int)dword_FFFFF8060BE04460;
    _R14 = dword_FFFFF8060BC394A0;
    is_mul_ok(0x758uLL, (unsigned int)dword_FFFFF8060BE04460);
    _RAX = sub_FFFFF8060BC317C0(v2, (char *)dword_FFFFF8060BC394A0 + v4, 0x758uLL);
    __asm { rcr     rax, 11h }
    v8 = (unsigned __int64)&dword_FFFFF8060BC394A0[262] + v4;
    DWORD2(v8) = *(_DWORD *)((char *)&dword_FFFFF8060BC394A0[334] + v4);
    sub_FFFFF8060BC1E788(&stru_FFFFF8060BE044B0, &v8);
    LODWORD(v4) = --dword_FFFFF8060BE04468;
    v6 = dword_FFFFF8060BE04460;
    sub_FFFFF8060BC316C0((__m128 *)&dword_FFFFF8060BC394A0[470 * dword_FFFFF8060BE04460], 0, 0x758uLL);
    if ( (_DWORD)v4 )
      dword_FFFFF8060BE04460 = (v6 + 1) % 0x3E8u;
    KeReleaseGuardedMutex(&Mutex);
    result = (unsigned int)dword_FFFFF8060BE04468;
  }
  else
  {
    result = 0xFFFFFFFFLL;
  }
  __asm { rcl     r14b, cl }
  return result;
}
```


# 深度特征扫描
```c++
char __fastcall sub_FFFFF8060BC1B1E4(PEPROCESS Process, __int64 a2, int a3)
{
  unsigned __int64 v6; // rax
  __int64 ProcessImageFileName; // rax
  HANDLE ProcessId; // rax
  __int64 v10; // [rsp+20h] [rbp-538h]
  struct _UNICODE_STRING UnicodeString; // [rsp+60h] [rbp-4F8h] BYREF
  _STRING v12; // [rsp+70h] [rbp-4E8h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+80h] [rbp-4D8h] BYREF
  _BYTE v14[6]; // [rsp+90h] [rbp-4C8h] BYREF
  __int128 v15; // [rsp+96h] [rbp-4C2h]
  __int64 v16; // [rsp+A6h] [rbp-4B2h]
  int v17; // [rsp+AEh] [rbp-4AAh]
  _DWORD v18[2]; // [rsp+B2h] [rbp-4A6h] BYREF
  __int128 v19; // [rsp+BAh] [rbp-49Eh]
  int v20; // [rsp+CAh] [rbp-48Eh]
  int v21; // [rsp+CEh] [rbp-48Ah]
  _DWORD v22[2]; // [rsp+D2h] [rbp-486h] BYREF
  __int128 v23; // [rsp+DAh] [rbp-47Eh]
  int v24; // [rsp+EAh] [rbp-46Eh]
  int v25; // [rsp+EEh] [rbp-46Ah]
  _BYTE v26[9]; // [rsp+F2h] [rbp-466h] BYREF
  __int128 v27; // [rsp+FBh] [rbp-45Dh]
  int v28; // [rsp+10Bh] [rbp-44Dh]
  int v29; // [rsp+10Fh] [rbp-449h]
  _BYTE v30[9]; // [rsp+113h] [rbp-445h] BYREF
  __int128 v31; // [rsp+11Ch] [rbp-43Ch]
  int v32; // [rsp+12Ch] [rbp-42Ch]
  __m128i si128; // [rsp+130h] [rbp-428h]
  __int128 v34; // [rsp+140h] [rbp-418h]
  char v35; // [rsp+150h] [rbp-408h]
  __int128 v36; // [rsp+151h] [rbp-407h]
  __int64 v37; // [rsp+161h] [rbp-3F7h]
  int v38; // [rsp+169h] [rbp-3EFh]
  __int16 v39; // [rsp+16Dh] [rbp-3EBh]
  char v40; // [rsp+16Fh] [rbp-3E9h]
  __int128 v41; // [rsp+170h] [rbp-3E8h] BYREF
  __m128 v42[8]; // [rsp+180h] [rbp-3D8h] BYREF
  __m128 v43[8]; // [rsp+200h] [rbp-358h] BYREF
  wchar_t Dst[64]; // [rsp+280h] [rbp-2D8h] BYREF
  __m128 v45; // [rsp+300h] [rbp-258h] BYREF
  __m128 SourceString[17]; // [rsp+410h] [rbp-148h] BYREF

  qmemcpy(v14, "client", sizeof(v14));
  v15 = 0LL;
  v16 = 0LL;
  v17 = 1818427392;
  qmemcpy(v18, "ient.dll", sizeof(v18));
  v19 = 0LL;
  v20 = 0;
  v21 = 1852112896;
  qmemcpy(v22, "gine.dll", sizeof(v22));
  v23 = 0LL;
  v24 = 0;
  v25 = 2003042304;
  qmemcpy(v26, "mcore.dll", sizeof(v26));
  v27 = 0LL;
  v28 = 0;
  v29 = 1635013376;
  qmemcpy(v30, "rtService", sizeof(v30));
  v31 = 0LL;
  v32 = 0;
  si128 = _mm_load_si128(xmmword_FFFFF8060BC33710);
  v34 = 0LL;
  v35 = 0;
  v36 = 0LL;
  v37 = 0LL;
  v38 = 0;
  v39 = 0;
  v40 = 0;
  sub_FFFFF8060BC316C0(&v45, 0, 0x104uLL);
  sub_FFFFF8060BC316C0(SourceString, 0, 0x104uLL);
  sub_FFFFF8060BC316C0(v42, 0, 0x80uLL);
  sub_FFFFF8060BC316C0(v43, 0, 0x80uLL);
  if ( !(unsigned __int8)sub_FFFFF8060BC2F1EC(
                           a2,
                           a3,
                           (unsigned int)v42,
                           128,
                           (__int64)v43,
                           128,
                           (__int64)&v45,
                           260,
                           (__int64)SourceString,
                           260,
                           (__int64)&v41,
                           (__int64)v14) )
    return 0;
  if ( !v42[0].m128_i8[0] && !v43[0].m128_i8[0] )
  {
    v6 = -1LL;
    do
      ++v6;
    while ( v45.m128_i8[v6] );
    if ( v6 <= 0x50 )
      return 0;
  }
  ProcessImageFileName = PsGetProcessImageFileName(Process);
  LODWORD(v10) = a3;
  swprintf_s(Dst, 0x40uLL, L"x:\\%I64x_%u\\%S", a2, v10, ProcessImageFileName);
  RtlInitUnicodeString(&DestinationString, Dst);
  RtlInitAnsiString(&v12, (PCSZ)SourceString);
  RtlAnsiStringToUnicodeString(&UnicodeString, &v12, 1u);
  ProcessId = PsGetProcessId(Process);
  sub_FFFFF8060BC18868((__int64)ProcessId, &DestinationString, 2u, &v41, 0LL, &UnicodeString);
  RtlFreeUnicodeString(&UnicodeString);
  return 1;
}
```

# 内存异常聚合
```c++
void __fastcall sub_FFFFF8060BC1B520(__int64 a1, _BYTE *a2, __int64 a3, _QWORD *a4)
{
  void *v5; // rdx
  int v6; // esi
  void *v7; // rcx
  int v8; // esi
  __int64 ProcessImageFileName; // rax
  SIZE_T MemoryInformationLength; // [rsp+20h] [rbp-E0h]
  SIZE_T MemoryInformationLengtha; // [rsp+20h] [rbp-E0h]
  int v12; // [rsp+38h] [rbp-C8h]
  int v13; // [rsp+40h] [rbp-C0h]
  int v14; // [rsp+48h] [rbp-B8h]
  ULONG_PTR ReturnLength; // [rsp+50h] [rbp-B0h] BYREF
  __int128 MemoryInformation; // [rsp+58h] [rbp-A8h] BYREF
  __int128 v17; // [rsp+68h] [rbp-98h]
  __int128 v18; // [rsp+78h] [rbp-88h]
  struct _UNICODE_STRING DestinationString; // [rsp+88h] [rbp-78h] BYREF
  struct _UNICODE_STRING v20; // [rsp+98h] [rbp-68h] BYREF
  wchar_t Dst[64]; // [rsp+B0h] [rbp-50h] BYREF
  wchar_t SourceString[256]; // [rsp+130h] [rbp+30h] BYREF

  if ( (*(_QWORD *)a2 & 0x8000000000000001uLL) != 1 || (*(_DWORD *)(a3 + 36) & 0xF0) != 0 )
  {
    v5 = (void *)*a4;
    if ( *a4 )
    {
      if ( *((_BYTE *)a4 + 16) )
      {
        v6 = *((_DWORD *)a4 + 2);
        v7 = (void *)a4[4];
        ReturnLength = 0LL;
        v8 = v6 << 12;
        MemoryInformation = 0LL;
        v17 = 0LL;
        v18 = 0LL;
        ZwQueryVirtualMemory(v7, v5, MemoryBasicInformation, &MemoryInformation, 0x30uLL, &ReturnLength);
        if ( (BYTE4(v18) & 0xF0) == 0
          && (*((_QWORD *)&v17 + 1) >= (unsigned __int64)v8 || !*((_QWORD *)&v17 + 1))
          && ((_QWORD)MemoryInformation != *a4 || (unsigned __int64)v8 >= *((_QWORD *)&v17 + 1)) )
        {
          sub_FFFFF8060BC1B1E4((PEPROCESS)a4[3], *a4, v8);
          ProcessImageFileName = PsGetProcessImageFileName(a4[3]);
          LODWORD(MemoryInformationLength) = v8;
          swprintf_s(Dst, 0x40uLL, L"x:\\%I64x_%u\\%S", *a4, MemoryInformationLength, ProcessImageFileName);
          RtlInitUnicodeString(&DestinationString, Dst);
          v14 = v18;
          v13 = DWORD2(v18);
          v12 = DWORD1(v18);
          LODWORD(MemoryInformationLengtha) = v8;
          swprintf_s(
            SourceString,
            0x100uLL,
            L"%I64x|%u|%I64x|%I64u|%x|%x|%x",
            *a4,
            MemoryInformationLengtha,
            (_QWORD)MemoryInformation,
            *((_QWORD *)&v17 + 1),
            v12,
            v13,
            v14);
          RtlInitUnicodeString(&v20, SourceString);
        }
      }
      *a4 = 0LL;
      a4[1] = 0LL;
      *((_BYTE *)a4 + 16) = 0;
    }
  }
  else
  {
    if ( *a4 )
    {
      ++a4[1];
    }
    else
    {
      *a4 = a1;
      a4[1] = 1LL;
    }
    if ( (*a2 & 0x20) != 0 )
      *((_BYTE *)a4 + 16) = 1;
  }
}

```

# Steam Overlay 检测
```c++
__int64 __fastcall sub_FFFFF8060C07C0AA(__int64 a1, int a2)
{
  unsigned int *v2; // rdi
  struct _OBJECT_NAME_INFORMATION *PoolWithTag; // rsi
  unsigned int i; // r15d
  __int64 ObjectType; // rax
  POBJECT_TYPE *v6; // r12
  char v7; // r13
  PVOID v8; // rcx
  wchar_t *v9; // rax
  unsigned int v10; // r14d
  struct _KPROCESS *v11; // r12
  PVOID *Object; // [rsp+0h] [rbp-248h]
  PVOID v14; // [rsp+18h] [rbp-230h] BYREF
  ULONG ReturnLength; // [rsp+20h] [rbp-228h] BYREF
  int v16; // [rsp+24h] [rbp-224h]
  PVOID P; // [rsp+28h] [rbp-220h] BYREF
  PEPROCESS Process; // [rsp+30h] [rbp-218h] BYREF
  unsigned int *v19; // [rsp+38h] [rbp-210h]
  unsigned int *v20; // [rsp+40h] [rbp-208h]
  struct _OBJECT_NAME_INFORMATION *v21; // [rsp+48h] [rbp-200h]
  __int128 v22; // [rsp+50h] [rbp-1F8h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+60h] [rbp-1E8h] BYREF
  struct _KAPC_STATE ApcState; // [rsp+70h] [rbp-1D8h] BYREF
  _DWORD v25[6]; // [rsp+A0h] [rbp-1A8h] BYREF
  _DWORD v26[6]; // [rsp+B8h] [rbp-190h] BYREF
  wchar_t SubStr[20]; // [rsp+D0h] [rbp-178h] BYREF
  wchar_t DstBuf[8]; // [rsp+F8h] [rbp-150h] BYREF
  __int128 v29; // [rsp+108h] [rbp-140h]
  wchar_t Dst[128]; // [rsp+120h] [rbp-128h] BYREF

  if ( a2 == 560 )
  {
    if ( Val )
    {
      v2 = (unsigned int *)sub_FFFFF8060BC2EEE4();
      v20 = v2;
      v19 = v2;
      if ( v2 )
      {
        PoolWithTag = (struct _OBJECT_NAME_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, 0x400uLL, 0x6F626A6Eu);
        v21 = PoolWithTag;
        if ( PoolWithTag )
        {
          for ( i = 0; i < *v2; ++i )
          {
            if ( sub_FFFFF8060BC2FDE8(*(void **)&v2[6 * i + 4]) )
            {
              ObjectType = ObGetObjectType(*(_QWORD *)&v2[6 * i + 4]);
              v6 = (POBJECT_TYPE *)ObjectType;
              if ( !qword_FFFFF8060BE49EB0 )
                sub_FFFFF8060BC18BFC(ObjectType);
              if ( qword_FFFFF8060BE49EB0 && (v6 == ExEventObjectType || v6 == (POBJECT_TYPE *)qword_FFFFF8060BE49EB0) )
              {
                v14 = 0LL;
                v7 = 0;
                if ( PsLookupProcessByProcessId((HANDLE)v2[6 * i + 2], &Process) < 0 )
                {
                  v8 = *(PVOID *)&v19[6 * i + 4];
                  v14 = v8;
                }
                else
                {
                  KeStackAttachProcess(Process, &ApcState);
                  ObReferenceObjectByHandle((HANDLE)HIWORD(v19[6 * i + 3]), 0, 0LL, 0, &v14, 0LL);
                  KeUnstackDetachProcess(&ApcState);
                  ObfDereferenceObject(Process);
                  v7 = 1;
                  v8 = v14;
                }
                if ( v8 )
                {
                  ReturnLength = 0;
                  if ( ObQueryNameString(v8, PoolWithTag, 0x400u, &ReturnLength) >= 0 )
                  {
                    if ( PoolWithTag->Name.Length )
                    {
                      if ( PoolWithTag->Name.Buffer )
                      {
                        _mm_lfence();
                        PoolWithTag->Name.Buffer[PoolWithTag->Name.Length] = 0;
                        wcscpy(SubStr, L"GameOverlayRender_");
                        v9 = wcsstr(PoolWithTag->Name.Buffer, SubStr);
                        if ( v9 )
                        {
                          wcscpy((wchar_t *)v26, L"-IPCWrapper");
                          if ( wcsstr(v9, (const wchar_t *)v26) )
                          {
                            _mm_lfence();
                            v22 = 0LL;
                            *(_OWORD *)DstBuf = 0LL;
                            v29 = 0LL;
                            i64tow_s((__int64)Val, DstBuf, 0x10uLL, 10);
                            if ( wcsstr(PoolWithTag->Name.Buffer, DstBuf) )
                            {
                              P = 0LL;
                              sub_FFFFF8060BC2F0EC((void *)v2[6 * i + 2], &P);
                              if ( P )
                              {
                                sub_FFFFF8060C08F880(v2[6 * i + 2], (const UNICODE_STRING *)P, 0xAu, &v22, 0LL, 0LL);
                                ExFreePoolWithTag(P, 0x66667061u);
                              }
                              else
                              {
                                v10 = 0;
                                v16 = 0;
                                while ( v10 < *v2 )
                                {
                                  if ( v2[6 * v10 + 2] == 4
                                    && sub_FFFFF8060BC2FDE8(*(void **)&v2[6 * v10 + 4])
                                    && (POBJECT_TYPE *)ObGetObjectType(*(_QWORD *)&v2[6 * v10 + 4]) == PsProcessType )
                                  {
                                    v11 = *(struct _KPROCESS **)&v2[6 * v10 + 4];
                                    if ( (HANDLE)v2[6 * i + 2] == PsGetProcessId(v11) )
                                    {
                                      v25[0] = 3801208;
                                      v25[1] = 6815836;
                                      v25[2] = 6553705;
                                      v25[3] = 6619236;
                                      v25[4] = 110;
                                      Object = (PVOID *)PsGetProcessImageFileName(v11);
                                      swprintf_s(Dst, 0x80uLL, L"%s\\%S", v25, Object);
                                      RtlInitUnicodeString(&DestinationString, Dst);
                                      sub_FFFFF8060C08F880(v2[6 * i + 2], &DestinationString, 0xAu, &v22, 0LL, 0LL);
                                      break;
                                    }
                                  }
                                  v16 = ++v10;
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  if ( v7 )
                    ObfDereferenceObject(v14);
                }
              }
            }
          }
          ExFreePoolWithTag(PoolWithTag, 0x6F626A6Eu);
        }
        ExFreePoolWithTag(v2, 0x70647276u);
      }
    }
  }
  return 0LL;
}

```

# 遍历目标进程的 VAD
```c++
__int64 __fastcall sub_FFFFF8060C07F756(__int64 _RCX, int a2)
{
  unsigned int v2; // r13d
  void *v4; // rbx
  int v5; // edi
  char v9; // al
  __int64 v10; // rcx
  int v11; // edx
  struct _MDL *Mdl; // rax
  struct _MDL *v13; // rbx
  PVOID MappedSystemVa; // r14
  __int64 v15; // rax
  PEPROCESS Process; // [rsp+28h] [rbp-280h] BYREF
  ULONG_PTR ReturnLength[2]; // [rsp+30h] [rbp-278h] BYREF
  HANDLE ProcessHandle; // [rsp+40h] [rbp-268h] BYREF
  __int128 MemoryInformation; // [rsp+48h] [rbp-260h] BYREF
  ULONG Length[4]; // [rsp+58h] [rbp-250h]
  __int128 v23; // [rsp+68h] [rbp-240h]
  __int64 v25; // [rsp+80h] [rbp-228h]
  struct _STRING v26; // [rsp+88h] [rbp-220h] BYREF
  struct _UNICODE_STRING UnicodeString; // [rsp+98h] [rbp-210h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+A8h] [rbp-200h] BYREF
  struct _KAPC_STATE ApcState; // [rsp+B8h] [rbp-1F0h] BYREF
  __int128 v30; // [rsp+E8h] [rbp-1C0h] BYREF
  wchar_t Dst[64]; // [rsp+100h] [rbp-1A8h] BYREF
  __m128 SourceString[17]; // [rsp+180h] [rbp-128h] BYREF

  _BitScanReverse(&_EAX, _RCX);
  __asm { rcl     ah, cl }
  if ( a2 == 560 )
  {
    v25 = *(int *)(_RCX + 528);
    if ( PsLookupProcessByProcessId((HANDLE)v25, &Process) >= 0 )
    {
      _mm_lfence();
      if ( ObOpenObjectByPointer(Process, 0x200u, 0LL, 0, 0LL, 0, &ProcessHandle) >= 0 )
      {
        MemoryInformation = 0LL;
        *(_OWORD *)Length = 0LL;
        v23 = 0LL;
        v4 = 0LL;
        ReturnLength[0] = 0LL;
        if ( PsGetProcessImageFileName(Process) )
        {
          v5 = 0;
          KeStackAttachProcess(Process, &ApcState);
          __asm { rcl     ch, cl }
          do
          {
            if ( ZwQueryVirtualMemory(
                   ProcessHandle,
                   v4,
                   MemoryBasicInformation,
                   &MemoryInformation,
                   0x30uLL,
                   ReturnLength) < 0
              || ReturnLength[0] != 48 )
            {
              break;
            }
            v9 = 0;
            v10 = MemoryInformation;
            if ( *(_BYTE *)MemoryInformation == 69 && *(_BYTE *)(MemoryInformation + 1) == 68
              || *(_BYTE *)MemoryInformation == 0x8B && *(_BYTE *)(MemoryInformation + 1) == 0xFF )
            {
              v9 = 1;
            }
            if ( !v9 )
            {
              v11 = 0;
              if ( (DWORD2(v23) & 0x1000000) == 0
                && ((BYTE4(v23) & 0x40) != 0 || (BYTE4(v23) & 0x20) != 0)
                && v5 <= 5
                && (unsigned __int64)(*(_QWORD *)&Length[2] - 0x4000LL) <= 0x63FBFFF )
              {
                v11 = 1;
              }
              if ( v11 )
              {
                Mdl = IoAllocateMdl((PVOID)MemoryInformation, Length[2], 0, 0, 0LL);
                v13 = Mdl;
                ReturnLength[1] = (ULONG_PTR)Mdl;
                if ( Mdl )
                {
                  MmProbeAndLockPages(Mdl, 1, IoReadAccess);
                  ++v5;
                  if ( (v13->MdlFlags & 5) != 0 )
                    MappedSystemVa = v13->MappedSystemVa;
                  else
                    LODWORD(MappedSystemVa) = (unsigned int)MmMapLockedPagesSpecifyCache(
                                                              v13,
                                                              0,
                                                              MmCached,
                                                              0LL,
                                                              0,
                                                              0x10u);
                  sub_FFFFF8060BC316C0(SourceString, 0, 0x104uLL);
                  if ( (unsigned __int8)sub_FFFFF8060BC2F800(
                                          (_DWORD)MappedSystemVa,
                                          Length[2],
                                          (unsigned int)&v30,
                                          (unsigned int)SourceString,
                                          259,
                                          0LL) )
                  {
                    swprintf_s(Dst, 0x40uLL, L"x:\\%d\\%S");
                    RtlInitUnicodeString(&DestinationString, Dst);
                    RtlInitAnsiString(&v26, (PCSZ)SourceString);
                    if ( v26.Length > 0x64u )
                    {
                      RtlAnsiStringToUnicodeString(&UnicodeString, &v26, 1u);
                      sub_FFFFF8060C08F880(v25, &DestinationString, 2u, &v30, 0LL, &UnicodeString);
                      RtlFreeUnicodeString(&UnicodeString);
                    }
                  }
                  MmUnlockPages(v13);
                  IoFreeMdl(v13);
                }
                v10 = MemoryInformation;
              }
            }
            _BitScanForward((unsigned int *)&v15, v2);
            _RAX = v15 >> v10;
            v4 = (void *)(*(_QWORD *)&Length[2] + v10);
            __asm { rcl     ah, 98h }
          }
          while ( (unsigned __int64)(*(_QWORD *)&Length[2] + v10) <= 0x7FFFFFFFFFFFFLL );
          KeUnstackDetachProcess(&ApcState);
        }
        ZwClose(ProcessHandle);
      }
      ObfDereferenceObject(Process);
    }
  }
  return 0LL;
}
```

# 特定对象/回调监控 
```c++
void __fastcall sub_FFFFF8060C1243E0(__int64 a1, __int64 a2, __int64 a3)
{
  char v4; // r10
  struct _OBJECT_NAME_INFORMATION *PoolWithTag; // rax
  UNICODE_STRING *p_Name; // rbx
  __int64 v11; // r9
  __int64 v12; // [rsp+0h] [rbp-98h]
  ULONG ReturnLength; // [rsp+10h] [rbp-88h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+18h] [rbp-80h] BYREF
  __int128 v15; // [rsp+28h] [rbp-70h] BYREF
  __m128 Dst[4]; // [rsp+40h] [rbp-58h] BYREF

  _CL = v4;
  __asm { rcl     esi, cl }
  sub_FFFFF8060BC316C0(Dst, 0, 0x40uLL);
  if ( !KeGetCurrentIrql() )
  {
    if ( a3 )
    {
      if ( (*(_DWORD *)a3 & 0x100) != 0 && (*(_DWORD *)a3 & 0x400) != 0 )
      {
        PoolWithTag = (struct _OBJECT_NAME_INFORMATION *)ExAllocatePoolWithTag(NonPagedPool, 0x400uLL, 0x6F626A6Eu);
        p_Name = &PoolWithTag->Name;
        if ( PoolWithTag )
        {
          if ( ObQueryNameString(*(PVOID *)(a3 + 40), PoolWithTag, 0x400u, &ReturnLength) >= 0 && p_Name->Length )
          {
            _mm_lfence();
            if ( (int)sub_FFFFF8060BC1B0A4(a2, p_Name, *(void **)(a3 + 8), 0LL, &v15) >= 0 )
            {
              _mm_lfence();
              v11 = *(_QWORD *)(a3 + 8);
              LODWORD(v12) = *(_DWORD *)(a3 + 24);
              DestinationString = 0LL;
              swprintf_s((wchar_t *)Dst, 0x20uLL, L"0x%I64x-%d", v11, v12);
              RtlInitUnicodeString(&DestinationString, (PCWSTR)Dst);
              sub_FFFFF8060C08F880(4LL, p_Name, 6u, &v15, 0LL, &DestinationString);
            }
          }
          ExFreePoolWithTag(p_Name, 0x6F626A6Eu);
        }
      }
    }
  }
}

```

# 页表扫描,自己执行页表扫描，寻找隐藏页面。
路径CR3 -> PML4 -> PDPT -> PD -> PT

```c++  
__int64 __fastcall sub_FFFFF8060C07E396(
        HANDLE ProcessId,
        void (__fastcall *a2)(void *, unsigned __int64, __int128 *, __int64 *))
{
  char v2; // si
  __int64 v3; // r15
  HANDLE v6; // rdi
  NTSTATUS v9; // edi
  NTSTATUS v11; // eax
  char v12; // dl
  __m128 *v16; // rdi
  __int64 v17; // r13
  __int64 v18; // rsi
  unsigned __int64 v19; // rcx
  __int64 v20; // rax
  unsigned __int64 i; // r12
  __int64 v22; // rcx
  __int64 v23; // rax
  unsigned __int64 j; // rsi
  __int64 v25; // rcx
  __int64 v26; // rax
  unsigned __int64 k; // r15
  __int64 v28; // rcx
  __int64 v29; // rax
  unsigned __int64 m; // r14
  void *v31; // rdi
  __m128 *v32; // rdi
  __int64 v33; // [rsp+20h] [rbp-188h] BYREF
  HANDLE ProcessHandle; // [rsp+28h] [rbp-180h] BYREF
  PEPROCESS Process; // [rsp+30h] [rbp-178h] BYREF
  __int64 v36; // [rsp+38h] [rbp-170h]
  ULONG_PTR ReturnLength; // [rsp+40h] [rbp-168h] BYREF
  void (__fastcall *v38)(void *, unsigned __int64, __int128 *, __int64 *); // [rsp+48h] [rbp-160h]
  unsigned __int64 v39; // [rsp+50h] [rbp-158h]
  unsigned __int64 v40; // [rsp+58h] [rbp-150h]
  __int64 v41; // [rsp+60h] [rbp-148h]
  unsigned __int64 v42; // [rsp+68h] [rbp-140h]
  __int64 v43; // [rsp+70h] [rbp-138h]
  unsigned __int64 v44; // [rsp+78h] [rbp-130h]
  __int128 MemoryInformation; // [rsp+80h] [rbp-128h] BYREF
  __int128 v46; // [rsp+90h] [rbp-118h]
  __int128 v47; // [rsp+A0h] [rbp-108h]
  __int64 v48; // [rsp+B0h] [rbp-F8h] BYREF
  __int128 v49; // [rsp+B8h] [rbp-F0h]
  PEPROCESS v50; // [rsp+C8h] [rbp-E0h]
  HANDLE v51; // [rsp+D0h] [rbp-D8h]
  struct _KAPC_STATE ApcState; // [rsp+D8h] [rbp-D0h] BYREF
  __m128 v53; // [rsp+110h] [rbp-98h] BYREF
  _BYTE v54[24]; // [rsp+128h] [rbp-80h] BYREF
  _BYTE v55[24]; // [rsp+140h] [rbp-68h] BYREF
  _BYTE v56[24]; // [rsp+158h] [rbp-50h] BYREF
  __int64 v57; // [rsp+180h] [rbp-28h]

  v57 = v3;
  _DI = __ROR1__((~(v2 ^ (1 << (v3 & 0xF))) & 0xFE) + 1, (char)ProcessId) - 38;
  v38 = a2;
  __asm { rcr     dil, cl }
  v6 = ProcessId;
  if ( !ProcessId )
    return 3221225485LL;
  Process = 0LL;
  ProcessHandle = 0LL;
  v33 = 0LL;
  if ( !sub_FFFFF8060BC2F004(&v33) || !v33 )
    return 3221225473LL;
  v9 = PsLookupProcessByProcessId(v6, &Process);
  if ( v9 >= 0 )
  {
    SHIBYTE(_DX) >>= 7;
    __asm
    {
      rcl     dh, 28h
      rcr     dx, 0B0h
    }
    v11 = ObOpenObjectByPointer(Process, 0x200u, 0LL, 0, 0LL, 0, &ProcessHandle);
    v9 = v11;
    if ( v11 >= 0 )
    {
      _DL = v12 + v11;
      MemoryInformation = 0LL;
      __asm { rcr     dl, cl }
      v46 = 0LL;
      v47 = 0LL;
      v48 = 0LL;
      v49 = 0LL;
      v50 = Process;
      v51 = ProcessHandle;
      KeStackAttachProcess(Process, &ApcState);
      sub_FFFFF8060BC316C0(&v53, 0, 0x60uLL);
      v16 = &v53;
      v17 = 4LL;
      v18 = 4LL;
      do
      {
        sub_FFFFF8060BC2EDDC(v16);
        v16 = (__m128 *)((char *)v16 + 24);
        --v18;
      }
      while ( v18 );
      v19 = __readcr3();
      if ( v19 )
      {
        v20 = sub_FFFFF8060BC2FD98(v19 & 0xFFFFFFFFF000LL, &v53);
        v33 = v20;
        for ( i = 0LL; ; ++i )
        {
          v44 = i;
          if ( i > 0xFF || !Val )
            break;
          v22 = *(_QWORD *)(v20 + 8 * i);
          if ( (v22 & 1) != 0 )
          {
            v23 = sub_FFFFF8060BC2FD98(v22 & 0xFFFFFFFFF000LL, v54);
            v43 = v23;
            if ( v23 )
            {
              for ( j = 0LL; ; ++j )
              {
                v42 = j;
                if ( j >= 0x200 || !Val )
                  break;
                v25 = *(_QWORD *)(v23 + 8 * j);
                if ( (v25 & 0x81) == 1 )
                {
                  v26 = sub_FFFFF8060BC2FD98(v25 & 0xFFFFFFFFF000LL, v55);
                  v41 = v26;
                  if ( v26 )
                  {
                    for ( k = 0LL; ; ++k )
                    {
                      v40 = k;
                      if ( k >= 0x200 || !Val )
                        break;
                      v28 = *(_QWORD *)(v26 + 8 * k);
                      if ( (v28 & 0x81) == 1 )
                      {
                        v29 = sub_FFFFF8060BC2FD98(v28 & 0xFFFFFFFFF000LL, v56);
                        v36 = v29;
                        if ( v29 )
                        {
                          for ( m = 0LL; ; ++m )
                          {
                            v39 = m;
                            if ( m >= 0x200 || !Val )
                              break;
                            if ( (*(_BYTE *)(v29 + 8 * m) & 1) != 0 )
                            {
                              v31 = (void *)((m | ((k | ((j | (i << 9)) << 9)) << 9)) << 12);
                              if ( (unsigned __int8)sub_FFFFF8060BC303D4(v31) == 1 )
                              {
                                if ( (unsigned __int64)v31 < (unsigned __int64)MemoryInformation
                                  || (unsigned __int64)v31 >= *((_QWORD *)&v46 + 1) + (_QWORD)MemoryInformation )
                                {
                                  ReturnLength = 0LL;
                                  ZwQueryVirtualMemory(
                                    ProcessHandle,
                                    v31,
                                    MemoryBasicInformation,
                                    &MemoryInformation,
                                    0x30uLL,
                                    &ReturnLength);
                                }
                                v38(v31, v36 + 8 * m, &MemoryInformation, &v48);
                              }
                            }
                            v29 = v36;
                          }
                        }
                      }
                      v26 = v41;
                    }
                  }
                }
                v23 = v43;
              }
            }
            v20 = v33;
          }
        }
      }
      v32 = &v53;
      do
      {
        sub_FFFFF8060BC2EEA4(v32);
        v32 = (__m128 *)((char *)v32 + 24);
        --v17;
      }
      while ( v17 );
      KeUnstackDetachProcess(&ApcState);
      v9 = 0;
    }
  }
  if ( ProcessHandle )
    ZwClose(ProcessHandle);
  if ( Process )
    ObfDereferenceObject(Process);
  return (unsigned int)v9;
}
```
