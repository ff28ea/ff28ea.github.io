messageTransfer.sys Analysis    version:2025_12_27

Imagebase   : FFFFF8060BC10000


# sub_FFFFF8060C096E4C  
## 检测cs2游戏进程状态
```c++  
  if ( !KeGetCurrentIrql() )
  {
    if ( a3 )
    {
      Process = 0LL;
      ProcessHandle = 0LL;
      v27 = 0;
      P = 0LL;
      if ( PsLookupProcessByProcessId(a2, &Process) >= 0 )
      {
        LOBYTE(_EDX) = _EDX - (_BYTE)a2;
        __asm { rcl     edx, 0A4h }
        if ( ObOpenObjectByPointer(Process, 0x200u, 0LL, 0, 0LL, 0, &ProcessHandle) >= 0 )
        {
          _R8D = (v11 + 478931759) ^ (1 << v12);
          __asm { rcl     r8b, cl }
          if ( ZwQueryInformationProcess(
                 ProcessHandle,
                 ProcessBasicInformation,
                 ProcessInformation,
                 0x30u,
                 &ReturnLength) >= 0 )
          {
            _mm_lfence();
            if ( (int)sub_FFFFF8060BC2F0EC(a2, &P) >= 0 )
            {
              ProcessImageFileName = 0LL;
              v31 = 0LL;
              if ( PsLookupProcessByProcessId(ProcessId, &v31) >= 0 )
              {
                ProcessImageFileName = (const char *)PsGetProcessImageFileName(v31);
                ObfDereferenceObject(v31);
              }
              if ( ProcessImageFileName )
              {
                v15 = (const char *)PsGetProcessImageFileName(Process);
                strcpy(Str2, "cs2.exe");
                if ( !stricmp(v15, Str2) )
                {
                  byte_FFFFF8060BE49C23 = 2;  //全局游戏状态标识
                  __asm { rcr     ch, cl }
                  Val = a2;
                  CS2_EProcess = (__int64)Process;// eprocess
                  if ( sub_FFFFF8060BC2FDE8((char *)Process + 0x28) )// check dtb 
                    CS2_CR3_DTB = *((_QWORD *)Process + 5);
                }
                KeStackAttachProcess(Process, &ApcState);
```
## 游戏退出时还原
```c++
   if ( !a3 && a2 == (HANDLE)(unsigned int)dword_FFFFF8060BE49EDC )
    {
      v24 = sub_FFFFF8060BC144F0();//cpuid 检测当前处理器类型 intel/amd
      //EPT hook还原
      if ( v24 == 1 )//Intel
      {
        sub_FFFFF8060BC15B88();
        sub_FFFFF8060BC1F878();
      }
      else if ( v24 == 2 )//AMD
      {
        sub_FFFFF8060BC135B4(v26, v25);
      }
      sub_FFFFF8060BC2C878();
    }
```

# sub_FFFFF8060BC21294   进程及进程线程扫描


## 遍历自维护的进程线程表，再获取系统进程表比对
```c++
  v8 = __rdtsc();
  do
  {
    for ( i = 0; i < *a1; ++i )
    {
      v10 = *(_QWORD *)&a1[2 * i + 2];
      v11 = *(_BYTE **)(v10 + 392);
      if ( *(_BYTE **)&a1[2 * i + 258] == v11 || !sub_FFFFF8060BC2FDE8(*(void **)(v10 + 392)) || *v11 != 6 )
        continue;
      v12 = ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4B0)(v11);//GetThreadId
      v13 = ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4B8)(v11);//GetProcessId
      v14 = v12 >> 2;
     // 处理 PID >= 0x10000 或 非法情况
      if ( v13 >= 0x10000
        || (v15 = 32 * ((unsigned __int64)v13 >> 2),
            ++*(_DWORD *)(v15 + a2),
            *(_DWORD *)(v15 + a2 + 4) = 257,
            *(_QWORD *)(v15 + a2 + 16) = v11,
            *(_DWORD *)(v15 + a2 + 24) = v12,
            byte_FFFFF8060BE4B4A6 != 1)
        || !CS2_EProcess
        || v12 == (_DWORD)Val
        || (v16 = *(_QWORD *)&v11[dword_FFFFF8060BE4B4D0], v16 == CS2_EProcess) //// [如果是游戏线程]
        && (*(_BYTE *)(v15 + a2 + 8) = 1, v16 == CS2_EProcess)
        || *(_BYTE *)(v15 + a2 + 8) != 1 )
      {
        if ( v12 < 0x10000 )
          goto LABEL_21;
      }
      else
      {  
        // [如果是外部线程 / 其他进程]
        ++*(_DWORD *)(v15 + a2 + 12);
        *(_BYTE *)(v15 + a2 + 8) = 0;
        if ( v12 < 0x10000 )
        {
      
          v17 = 32LL * v14;
          ++*(_DWORD *)(v17 + a2 + 12);
          *(_BYTE *)(v17 + a2 + 4) = 2;
LABEL_21:
          _mm_lfence();
          v18 = 32LL * v14;
          ++*(_DWORD *)(v18 + a2);
          *(_WORD *)(v18 + a2 + 4) = 258;
          *(_BYTE *)(v18 + a2 + 6) = 0;
          *(_QWORD *)(v18 + a2 + 16) = ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4C0)(v11);
        }
      }
    }
    v19 = __rdtsc();
  }
  while ( (((unsigned __int64)HIDWORD(v19) << 32) | (unsigned int)v19) - v8 <= qword_FFFFF8060BE4B4D8 );
  v53 = 0;
  ((void (__fastcall *)(__int64, _QWORD, _QWORD, unsigned int *))qword_FFFFF8060BE4B3F8)(5LL, 0LL, 0LL, &v53);//ZwQuerySystemInformation
  v53 += 4096;
  PoolWithTag = (unsigned int *)ExAllocatePoolWithTag(NonPagedPool, v53, 0x796B6Bu);
  if ( !PoolWithTag )
    return 3221225473LL;
  v21 = ((__int64 (__fastcall *)(__int64, unsigned int *, _QWORD, unsigned int *))qword_FFFFF8060BE4B3F8)(
          5LL,
          PoolWithTag,
          v53,
          &v53);//ZwQuerySystemInformation
  if ( v21 >= 0 )
  {
    for ( j = PoolWithTag; ; j = (unsigned int *)((char *)j + v26) )
    {
      v23 = j[20];//// NumberOfThreads
      if ( (unsigned int)v23 < 0x10000 )
        *(_BYTE *)(32 * (v23 >> 2) + a2 + 5) = 0;

      for ( k = 0; k < j[1]; ++k )
      {
        v25 = j[20 * k + 76];
        if ( (unsigned int)v25 < 0x10000 )
          *(_BYTE *)(32 * (v25 >> 2) + a2 + 5) = 0;
      }
      v26 = *j;
      if ( !(_DWORD)v26 )
        break;
    }
  }
  ExFreePoolWithTag(PoolWithTag, 0x796B6Bu);

```

## 再次采样
```c++
sub_FFFFF8060BC2C8B8(3LL);
  v27 = __rdtsc();
  do
  {
    for ( m = 0; m < *a1; ++m )
    {
      v29 = *(_QWORD *)&a1[2 * m + 2];
      v30 = *(_BYTE **)(v29 + 392);
      if ( *(_BYTE **)&a1[2 * m + 258] != v30 && sub_FFFFF8060BC2FDE8(*(void **)(v29 + 392)) && *v30 == 6 )
      {
        v31 = ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4B0)(v30);//GetThreadId
        v32 = ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4B8)(v30);//GetProcessId
        if ( v32 < 0x10000 )
        {
          v33 = 32 * ((unsigned __int64)v32 >> 2);
          if ( *(_BYTE *)(v33 + a2 + 5) )
          {
            //这是一个 "活跃" 但 "可能脱链" 的线程  
            if ( *(_BYTE **)(v33 + a2 + 16) == v30 )
              *(_BYTE *)(v33 + a2 + 6) = 1;//可疑标记
          }
        }
        if ( v31 < 0x10000 )
        {
          v34 = 32LL * (v31 >> 2);
          if ( *(_BYTE *)(v34 + a2 + 5) )
          {
            _mm_lfence();
            if ( *(_QWORD *)(v34 + a2 + 16) == ((__int64 (__fastcall *)(_BYTE *))qword_FFFFF8060BE4B4C0)(v30) )
              *(_BYTE *)(v34 + a2 + 6) = 1;
          }
        }
      }
    }
    v35 = __rdtsc();
  }
  while ( (((unsigned __int64)HIDWORD(v35) << 32) | (unsigned int)v35) - v27 <= qword_FFFFF8060BE4B4D8 );

```
## 最终判定
```c++
  while ( v36 < dword_FFFFF8060BC3607C )//样本活跃记录
  {
    v40 = 32LL * v36;
    if ( *(_BYTE *)(v40 + a2 + 6) == 1 )
    {
      if ( *(_BYTE *)(v40 + a2 + 4) == 1 )
      {
        ++a3[1];
        if ( v37 < 0xC )
        {
          v41 = v37++;
          v54 = v37;
          v42 = 5 * v41;
          a3[v42 + 66] = 4 * v36;
          a3[v42 + 67] = *(_DWORD *)(v40 + a2);
          a3[v42 + 69] = *(_DWORD *)(v40 + a2 + 24);
          a3[v42 + 68] = *(_DWORD *)(v40 + a2 + 12);
        }
      }
      if ( *(_BYTE *)(v40 + a2 + 4) != 2 )
        goto LABEL_64;
      ++*a3;
      if ( v38 < 0xC )
      {
        v43 = v38++;
        v44 = 5 * v43;
        a3[v44 + 6] = 4 * v36;
        a3[v44 + 7] = *(_DWORD *)(v40 + a2);
        a3[v44 + 8] = *(_DWORD *)(v40 + a2 + 12);
      }
    }
    if ( *(_BYTE *)(v40 + a2 + 4) == 2 && !*(_BYTE *)(v40 + a2 + 6) && *(_DWORD *)(v40 + a2) > 0x249F0u )//外部高活跃线程  如cpu死循环占用的线程
    {
      ++a3[2];
      if ( v39 < 0xC )
      {
        v45 = v39++;
        v46 = 5 * v45;
        a3[v46 + 126] = 4 * v36;
        a3[v46 + 127] = *(_DWORD *)(v40 + a2);
        a3[v46 + 128] = *(_DWORD *)(v40 + a2 + 12);
      }
    }
LABEL_64:
    if ( *(_BYTE *)(v40 + a2 + 4) == 1 )//查找隐藏的线程，活跃但是系统函数找不到。如断链
    {
      if ( *(_DWORD *)(v40 + a2 + 12) > 0x32u )
      {
        Thread = 0LL;
        if ( PsLookupThreadByThreadId((HANDLE)(4 * v36), &Thread) < 0 )
        {
          ++a3[3];
          if ( v51 < 3 )
          {
            v47 = 5LL * v51;
            a3[v47 + 186] = 4 * v36;
            a3[v47 + 187] = *(_DWORD *)(v40 + a2);
            a3[v47 + 189] = *(_DWORD *)(v40 + a2 + 24);
            a3[v47 + 188] = *(_DWORD *)(v40 + a2 + 12);
            ++v51;
          }
        }
        else
        {
          ObfDereferenceObject(Thread);
        }
        v37 = v54;
      }
      if ( *(_BYTE *)(v40 + a2 + 4) == 1 && *(_DWORD *)(v40 + a2 + 12) > 0x32u )
      {
        ++a3[4];
        if ( v3 < 0xC )
        {
          v48 = v3++;
          v49 = 5 * v48;
          a3[v49 + 201] = 4 * v36;
          a3[v49 + 202] = *(_DWORD *)(v40 + a2);
          a3[v49 + 204] = *(_DWORD *)(v40 + a2 + 24);
          a3[v49 + 203] = *(_DWORD *)(v40 + a2 + 12);
        }
      }
    }
    ++v36;
  }

```

# sub_FFFFF8060BC2185C 进程活动检测函数
扫描并报告异常活跃的外部进程
```c++
__int64 __fastcall sub_FFFFF8060BC2185C(unsigned int *a1, __int64 a2, _DWORD *a3)
{
  unsigned int v3; // esi
  unsigned __int64 v7; // rbx
  unsigned __int64 v8; // r13
  unsigned int i; // r15d
  __int64 v10; // rcx
  __int64 v11; // r12
  unsigned int v12; // ebx
  unsigned int v13; // eax
  unsigned int v14; // r9d
  unsigned __int64 v15; // rcx
  __int64 v16; // rdx
  __int64 v17; // rax
  __int64 v18; // rax
  unsigned __int64 v19; // rax
  unsigned int v20; // r15d
  unsigned int v21; // r14d
  __int64 v22; // rcx
  __int64 v23; // rdx
  __int64 v24; // rcx

  v3 = 0;
  if ( !qword_FFFFF8060BE4B4E8 )
  {
    v7 = __rdtsc();
    sub_FFFFF8060BC2C8B8(3u);
    qword_FFFFF8060BE4B4E8 = __rdtsc() - v7;
  }
  if ( !a3 || !a2 || !a1 )
    return 3221225473LL;
  v8 = __rdtsc();
  do
  {
    for ( i = 0; i < *a1; ++i )
    {
      v10 = *(_QWORD *)&a1[2 * i + 2];
      v11 = *(_QWORD *)(v10 + 392);
      if ( *(_QWORD *)&a1[2 * i + 258] != v11 && sub_FFFFF8060BC2FDE8(*(void **)(v10 + 392)) )
      {
        v12 = ((__int64 (__fastcall *)(__int64))qword_FFFFF8060BE4B4B0)(v11);
        v13 = ((__int64 (__fastcall *)(__int64))qword_FFFFF8060BE4B4B8)(v11);
        v14 = v12 >> 2;
        if ( v13 >= 0x10000
          || (v15 = 2 * ((unsigned __int64)v13 >> 2),
              ++*(_DWORD *)(a2 + 8 * v15),
              *(_BYTE *)(a2 + 8 * v15 + 4) = 1,
              *(_DWORD *)(a2 + 8 * v15 + 12) = v12,
              byte_FFFFF8060BE4B4A6 != 1)
          || !CS2_EProcess
          || v12 == (_DWORD)Val
          || (v16 = *(_QWORD *)((unsigned int)dword_FFFFF8060BE4B4D0 + v11), v16 == CS2_EProcess)
          && (*(_BYTE *)(a2 + 16 * ((unsigned __int64)v13 >> 2) + 5) = 1, v16 == CS2_EProcess)
          || *(_BYTE *)(a2 + 16 * ((unsigned __int64)v13 >> 2) + 5) != 1 )
        {
          if ( v12 < 0x10000 )
            goto LABEL_20;
        }
        else
        {
          ++*(_DWORD *)(a2 + 16 * ((unsigned __int64)v13 >> 2) + 8);
          *(_BYTE *)(a2 + 16 * ((unsigned __int64)v13 >> 2) + 5) = 0;
          if ( v12 < 0x10000 )
          {
            v17 = 2LL * v14;
            ++*(_DWORD *)(a2 + 8 * v17 + 8);
            *(_BYTE *)(a2 + 8 * v17 + 4) = 2;
LABEL_20:
            if ( v12 != (_DWORD)Val )
            {
              v18 = 2LL * v14;
              ++*(_DWORD *)(a2 + 8 * v18);
              *(_BYTE *)(a2 + 8 * v18 + 4) = 2;
            }
          }
        }
      }
    }
    v19 = __rdtsc();
  }
  while ( (((unsigned __int64)HIDWORD(v19) << 32) | (unsigned int)v19) - v8 <= qword_FFFFF8060BE4B4E8 );
  v20 = 0;
  v21 = 0;
  if ( dword_FFFFF8060BC36088 )
  {
    while ( 1 )
    {
      // [检测逻辑 1]：高频外部进程检测
      // 条件 A: 标记为 2 (External)
      // 条件 B: 计数器 > 0x4E20 (20,000)
      if ( *(_BYTE *)(a2 + 16LL * v21 + 4) != 2 || *(_DWORD *)(a2 + 16LL * v21) <= 0x4E20u )
        goto LABEL_30;

    // 过滤掉当前进程 (驱动自己的宿主进程)
      if ( PsGetCurrentProcessId() != (HANDLE)(4 * v21) )
        break;
LABEL_34:
      if ( ++v21 >= dword_FFFFF8060BC36088 )
        return 0LL;
    }
    ++*a3;
    if ( v3 < 0x18 )
    {
      v22 = 2LL * v3++;
      a3[2 * v22 + 2] = 4 * v21;
      a3[2 * v22 + 3] = *(_DWORD *)(a2 + 16LL * v21);
      a3[2 * v22 + 4] = *(_DWORD *)(a2 + 16LL * v21 + 8);
    }
LABEL_30:
    if ( *(_BYTE *)(a2 + 16LL * v21 + 4) == 1 && *(_DWORD *)(a2 + 16LL * v21 + 8) > 1u )
    {
      ++a3[1];
      if ( v20 < 0x18 )
      {
        v23 = 2LL * v20;
        v24 = v20++ + 25LL;
        a3[2 * v23 + 98] = 4 * v21;
        a3[2 * v23 + 99] = *(_DWORD *)(a2 + 16LL * v21);
        a3[4 * v24] = *(_DWORD *)(a2 + 16LL * v21 + 8);
        a3[2 * v23 + 101] = *(_DWORD *)(a2 + 16LL * v21 + 12);
      }
    }
    goto LABEL_34;
  }
  return 0LL;
}
```

# sub_FFFFF8060BC2BB88   附加cs2游戏进程
```c++
    Process = 0LL;
  if ( PsLookupProcessByProcessId((HANDLE)(unsigned int)v5, &Process) < 0 )
    return 0LL;
  CS2_EProcess = (__int64)Process;
  Val = v5;
  byte_FFFFF8060BE49C23 = *(_BYTE *)(a1 + 0x234);
  if ( sub_FFFFF8060BC2FDE8((char *)Process + 40) )
    CS2_CR3_DTB = *((_QWORD *)Process + 5);
  if ( Process )
    ObfDereferenceObject(Process);
```

