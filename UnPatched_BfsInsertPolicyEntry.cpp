
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void BfsInsertPolicyEntry
               (dword *param_1,undefined8 param_2,longlong sharedPushLock,undefined8 param_4,
               longlong token_user_info_class,longlong param_6,longlong *param_7)

{
  longlong *plVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  code *pcVar4;
  bool bVar5;
  bool bVar6;
  uint uVar7;
  longlong lVar8;
  longlong lVar9;
  longlong lVar10;
  longlong lVar11;
  ulonglong uVar12;
  undefined8 uVar13;
  dword *pdVar14;
  undefined1 auStackY_118 [32];
  undefined8 local_e0;
  char local_d8;
  longlong local_d0;
  longlong local_c8;
  undefined8 local_c0;
  longlong local_b8;
  dword *local_b0;
  undefined8 local_a8;
  dword local_a0 [4];
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 *local_60;
  undefined8 local_58;
  ulonglong local_50;
  
  local_50 = __security_cookie ^ (ulonglong)auStackY_118;
  lVar10 = 0;
  local_d0 = token_user_info_class;
  local_c8 = param_6;
  bVar5 = false;
  local_90 = 0;
  uStack_88 = 0;
  local_a8 = 0;
  local_a0[0] = 0;
  local_a0[1] = 0;
  local_a0[2] = 0;
  local_a0[3] = 0;
  local_b8 = 0;
  local_d8 = '\0';
  bVar6 = false;
  local_e0 = param_2;
  local_c0 = param_4;
  local_b0 = param_1;
  KeEnterCriticalRegion();
  ExAcquirePushLockExclusiveEx(sharedPushLock,0);
  uVar12 = *(ulonglong *)(sharedPushLock + 8);
  lVar8 = BfsLookupPolicyEntryHashTable(uVar12,local_c0,token_user_info_class,param_6);
  if (lVar8 == 0) {
    lVar9 = ExAllocatePool2(0x100,(ulonglong)*(byte *)(local_d0 + 1) * 4 + 8,0x53736642);
    if ((lVar9 == 0) ||
       (lVar10 = ExAllocatePool2(0x100,(ulonglong)*(byte *)(param_6 + 1) * 4 + 8,0x53736642),
       lVar10 == 0)) goto LAB_00006876;
    uVar12 = (ulonglong)((uint)*(byte *)(local_d0 + 1) * 4 + 8);
    uVar7 = RtlCopySid(uVar12,lVar9,local_d0);
    if ((int)uVar7 < 0) {
LAB_0000690c:
      if (3 < .data) {
        local_e0 = CONCAT44(local_e0._4_4_,uVar7);
LAB_0000688e:
        local_60 = &local_e0;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(uVar12,&DAT_00013c91);
      }
    }
    else {
      uVar12 = (ulonglong)((uint)*(byte *)(local_c8 + 1) * 4 + 8);
      uVar7 = RtlCopySid(uVar12,lVar10,local_c8);
      if ((int)uVar7 < 0) goto LAB_0000690c;
      lVar8 = ExAllocatePool2(0x100,0x98,0x45736642);
      if (lVar8 != 0) {
        LOCK();
        *(int *)(lVar8 + 0x90) = *(int *)(lVar8 + 0x90) + 1;
        UNLOCK();
        lVar11 = ExAllocatePool2(0x40,0x18,0x76736642);
        *(longlong *)(lVar8 + 0x28) = lVar11;
        if (lVar11 != 0) {
          *(longlong *)(lVar8 + 0x18) = lVar9;
          *(longlong *)(lVar8 + 0x20) = lVar10;
          *(undefined4 *)(lVar8 + 0x38) = 0x10000001;
          *(undefined4 *)(lVar8 + 0x68) = 0;
          *(undefined8 *)(lVar8 + 0x70) = 0;
          *(undefined8 *)(lVar8 + 0x78) = 0;
          *(undefined2 *)(lVar8 + 0x72) = 0;
          *(undefined8 *)(lVar8 + 0x78) = 0;
          *(undefined8 *)(lVar8 + 0x80) = 0;
          *(undefined8 *)(lVar8 + 0x88) = 0;
          *(undefined2 *)(lVar8 + 0x82) = 0;
          *(undefined8 *)(lVar8 + 0x88) = 0;
          KeInitializeEvent(lVar11,0,0);
          uVar12 = *(ulonglong *)(sharedPushLock + 8);
          uVar7 = BfsInsertEntryHashTable(uVar12,local_c0,lVar8);
          if (-1 < (int)uVar7) {
            LOCK();
            *(int *)(lVar8 + 0x90) = *(int *)(lVar8 + 0x90) + 1;
            UNLOCK();
            plVar1 = (longlong *)(sharedPushLock + 0x10);
            local_d8 = '\x01';
            if ((longlong *)*plVar1 == plVar1) {
              ExSetTimer(*(undefined8 *)(sharedPushLock + 0x20),0xffffffffee1e5d00,300000000);
            }
            puVar2 = *(undefined8 **)(sharedPushLock + 0x18);
            plVar3 = (longlong *)(lVar8 + 0x40);
            if ((longlong *)*puVar2 != plVar1) goto LAB_00006d58;
            *plVar3 = (longlong)plVar1;
            *(undefined8 **)(lVar8 + 0x48) = puVar2;
            *puVar2 = plVar3;
            *(longlong **)(sharedPushLock + 0x18) = plVar3;
            LOCK();
            *(undefined8 *)(lVar8 + 0x60) = _DAT_fffff78000000014;
            UNLOCK();
            goto LAB_00006a67;
          }
          goto LAB_0000690c;
        }
      }
LAB_00006876:
      uVar12 = 0xc0000017;
      uVar7 = 0xc0000017;
      if (3 < .data) {
        local_e0 = CONCAT44(local_e0._4_4_,0xc0000017);
        uVar7 = 0xc0000017;
        goto LAB_0000688e;
      }
    }
LAB_00006bb9:
    ExReleasePushLockExclusiveEx(sharedPushLock);
    KeLeaveCriticalRegion();
    bVar5 = false;
    bVar6 = false;
    if ((int)uVar7 < 0) {
LAB_00006be6:
      if (lVar8 != 0) {
LAB_00006beb:
        BfsDereferencePolicyEntryEx(lVar8,'\0');
      }
      if (local_d8 != '\0') {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusiveEx(sharedPushLock,0);
        lVar8 = BfsLookupPolicyEntryHashTable
                          (*(undefined8 *)(sharedPushLock + 8),local_c0,local_d0,local_c8);
        if (lVar8 == 0) {
          ExReleasePushLockExclusiveEx(sharedPushLock,0);
          KeLeaveCriticalRegion();
        }
        else {
          plVar1 = (longlong *)(lVar8 + 0x40);
          *(undefined4 *)(lVar8 + 0x38) = 1;
          lVar11 = *plVar1;
          if ((*(longlong **)(lVar11 + 8) != plVar1) ||
             (plVar3 = *(longlong **)(lVar8 + 0x48), (longlong *)*plVar3 != plVar1)) {
LAB_00006d58:
            pcVar4 = (code *)swi(0x29);
            (*pcVar4)(3);
            pcVar4 = (code *)swi(3);
            (*pcVar4)();
            return;
          }
          *plVar3 = lVar11;
          *(longlong **)(lVar11 + 8) = plVar3;
          uVar12 = Feature_Servicing_BfsGAFeature__private_IsEnabledDeviceUsageNoInline();
          if ((int)uVar12 != 0) {
            *plVar1 = 0;
            *(undefined8 *)(lVar8 + 0x48) = 0;
          }
          ExReleasePushLockExclusiveEx(sharedPushLock);
          KeLeaveCriticalRegion();
          KeSetEvent(*(undefined8 *)(lVar8 + 0x28),0,0);
          BfsDereferencePolicyEntryEx(lVar8,'\0');
        }
      }
      if (bVar5) {
        RtlFreeUnicodeString(local_a0);
      }
      if (bVar6) {
        RtlFreeUnicodeString(&local_90);
      }
      if (lVar9 != 0) {
        ExFreePoolWithTag(lVar9,0);
      }
      if (lVar10 != 0) {
        ExFreePoolWithTag(lVar10,0);
      }
    }
    if (local_b8 != 0) {
      FltClose();
    }
  }
  else {
    lVar9 = lVar10;
    if ((*(uint *)(lVar8 + 0x38) >> 0x1c & 1) == 0) {
      if (*(uint *)(lVar8 + 0x38) != 2) {
        uVar7 = 0xc0000001;
        goto LAB_0000690c;
      }
      *(undefined4 *)(lVar8 + 0x38) = 0x10000001;
      KeResetEvent(*(undefined8 *)(lVar8 + 0x28));
      LOCK();
      *(int *)(lVar8 + 0x90) = *(int *)(lVar8 + 0x90) + 1;
      UNLOCK();
LAB_00006a67:
      ExReleasePushLockExclusiveEx(sharedPushLock,0);
      KeLeaveCriticalRegion();
      pdVar14 = local_a0;
      uVar7 = RtlConvertSidToUnicodeString(pdVar14,local_d0,1);
      if (-1 < (int)uVar7) {
        pdVar14 = (dword *)&local_90;
        bVar5 = true;
        uVar7 = RtlConvertSidToUnicodeString(pdVar14,local_c8,1);
        if (-1 < (int)uVar7) {
          bVar6 = true;
          pdVar14 = local_b0;
          uVar7 = BfsOpenPolicyDirectory(local_b0,local_e0,local_a0,'\0',&local_b8);
          if ((-1 < (int)uVar7) &&
             (pdVar14 = local_b0,
             uVar7 = BfsCreateStorage(local_b0,local_e0,local_b8,&local_90,&local_a8),
             -1 < (int)uVar7)) {
            RtlFreeUnicodeString(local_a0);
            RtlFreeUnicodeString(&local_90);
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusiveEx(sharedPushLock);
            *(undefined8 *)(lVar8 + 0x30) = local_a8;
            *(undefined4 *)(lVar8 + 0x38) = 0x10000000;
            KeSetEvent(*(undefined8 *)(lVar8 + 0x28),0,0);
            *param_7 = lVar8;
            goto LAB_00006bb9;
          }
        }
      }
      if (3 < .data) {
        local_e0 = CONCAT44(local_e0._4_4_,uVar7);
        local_60 = &local_e0;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(pdVar14,&DAT_00013c91);
      }
      goto LAB_00006be6;
    }
    LOCK();
    *(int *)(lVar8 + 0x90) = *(int *)(lVar8 + 0x90) + 1;
    UNLOCK();
    ExReleasePushLockExclusiveEx(sharedPushLock);
    KeLeaveCriticalRegion();
    if (*(int *)(lVar8 + 0x38) == 0x10000001) {
      uVar13 = *(undefined8 *)(lVar8 + 0x28);
      KeWaitForSingleObject(uVar13,0,0,0);
      if (*(int *)(lVar8 + 0x38) != 0x10000000) {
        if (3 < .data) {
          local_e0 = CONCAT44(local_e0._4_4_,0xc0000001);
          local_60 = &local_e0;
          local_58 = 4;
          _tlgWriteTransfer_EtwWriteTransfer(uVar13,&DAT_00013c91);
          lVar10 = 0;
          lVar9 = 0;
        }
        goto LAB_00006beb;
      }
    }
    *param_7 = lVar8;
  }
  __security_check_cookie(local_50 ^ (ulonglong)auStackY_118);
  return;
}

