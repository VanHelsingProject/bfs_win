
void BfsCheckAndApplyPolicy
               (dword *param_1,longlong param_2,dword *param_3,dword *param_4,longlong *param_5)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  ushort *puVar4;
  undefined8 uVar5;
  ulonglong uVar6;
  longlong lVar7;
  dword *pdVar8;
  longlong lVar9;
  undefined1 auStackY_118 [32];
  uint local_e8;
  char local_e4;
  char local_e3 [3];
  longlong local_e0;
  longlong local_d8;
  undefined8 *local_d0;
  undefined8 *local_c8;
  dword *local_c0;
  longlong local_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 local_a0;
  undefined8 uStack_98;
  ushort local_90 [24];
  uint *local_60;
  undefined8 local_58;
  ulonglong local_50;
  
  local_50 = __security_cookie ^ (ulonglong)auStackY_118;
  local_e3[0] = '\0';
  local_d0 = (undefined8 *)0x0;
  local_e0 = 0;
  local_d8 = 0;
  local_c8 = (undefined8 *)0x0;
  local_b0 = 0;
  uStack_a8 = 0;
  pdVar8 = param_3;
  uVar3 = SeQueryInformationToken(param_3,1,&local_d0);
  uVar1 = local_e8;
  if ((-1 < (int)uVar3) &&
     (pdVar8 = param_3, uVar3 = SeQueryInformationToken(param_3,0x1f,&local_c8), uVar1 = local_e8,
     -1 < (int)uVar3)) {
    uVar3 = FltGetFileNameInformation(param_4,0x101,&local_d8);
    if (uVar3 == 0xc0000201) {
      local_b8 = 0;
      local_c0 = param_3;
      uVar3 = BfsQueueDeferredWorkItemAndWait
                        ((longlong)param_1,param_2,param_4,&local_c0,
                         BfsQueryFileNameInformationCallback);
      local_d8 = local_b8;
    }
    pdVar8 = (dword *)(ulonglong)uVar3;
    uVar1 = local_e8;
    if (-1 < (int)uVar3) {
      bVar2 = BfsPolicyEntryExists(param_1,param_2,0x16200,(byte *)*local_d0,(byte *)*local_c8);
      if (bVar2 == 0) {
        pdVar8 = (dword *)&gBfsPolicyTable;
        uVar5 = BfsGetNotPresentPolicyEntry(0x16200,(byte *)*local_d0,(byte *)*local_c8,&local_e0);
        lVar9 = local_e0;
        uVar3 = (uint)uVar5;
        uVar1 = local_e8;
        if ((int)(uint)uVar5 < 0) goto joined_r0x00004c71;
LAB_00004b82:
        local_e4 = '\0';
        pdVar8 = (dword *)0x0;
        uVar3 = RtlCheckTokenCapability
                          (0,*(undefined8 *)(*(longlong *)SeExports_exref + 0x250),&local_e4);
        if ((int)uVar3 < 0) {
          if (uVar3 != 0xc0000022) goto LAB_00004bd8;
LAB_00004d3f:
          if ((local_d8 == 0) &&
             (uVar3 = FltGetFileNameInformation(param_4,0x101,&local_d8), pdVar8 = param_4,
             (int)uVar3 < 0)) goto LAB_00004bd8;
          lVar7 = *param_5;
          if (lVar7 != 0) {
LAB_00004da8:
            *(undefined4 *)(lVar7 + 8) = 1;
            FltReferenceFileNameInformation(local_d8);
            *(longlong *)(*param_5 + 0x30) = local_d8;
            *(longlong *)(*param_5 + 0x40) = lVar9;
            LOCK();
            *(int *)(lVar9 + 0x90) = *(int *)(lVar9 + 0x90) + 1;
            UNLOCK();
            *(uint *)*param_5 = *(uint *)*param_5 | 1;
            lVar9 = local_e0;
            uVar1 = local_e8;
            goto LAB_00004de8;
          }
          pdVar8 = &IMAGE_NT_HEADERS64_000000f0.FileHeader.NumberOfSymbols;
          lVar7 = ExAllocatePool2(0x100,0x58,0x43736642);
          *param_5 = lVar7;
          if (lVar7 != 0) goto LAB_00004da8;
          uVar1 = local_e8;
          if (DAT_00016000 < 4) goto LAB_00004de8;
          local_e8 = 0xc0000017;
        }
        else {
          if (local_e4 == '\0') goto LAB_00004d3f;
          pdVar8 = param_3;
          uVar3 = BfsFileInPublisherDirectory(param_3,local_d8,(ushort *)local_e3,&local_b0);
          if ((int)uVar3 < 0) goto LAB_00004bd8;
          if (local_e3[0] == '\0') goto LAB_00004d3f;
          if (lVar9 == 0) {
LAB_00004c37:
            pdVar8 = param_1;
            uVar3 = BfsGetPolicyEntry(param_1,param_2,0x16200,(byte *)*local_d0,(byte *)*local_c8,
                                      &local_e0);
            lVar9 = local_e0;
            uVar1 = local_e8;
            if ((int)uVar3 < 0) goto joined_r0x00004c71;
          }
          else if (*(int *)(lVar9 + 0x38) == 2) {
            BfsDereferencePolicyEntryEx(lVar9,'\0');
            goto LAB_00004c37;
          }
          uVar6 = Feature_1827994938__private_IsEnabledDeviceUsageNoInline();
          if (((int)uVar6 != 0) && (*(int *)(lVar9 + 0x38) == 0x10000001)) {
            uVar3 = BfsGetPolicyEntry(param_1,param_2,0x16200,(byte *)*local_d0,(byte *)*local_c8,
                                      &local_e0);
            lVar9 = local_e0;
            pdVar8 = param_1;
            uVar1 = local_e8;
            if ((int)uVar3 < 0) goto joined_r0x00004c71;
            BfsDereferencePolicyEntryEx(local_e0,'\0');
          }
          BfsAddOrModifyEntry(*(longlong *)(lVar9 + 0x30),2,1,2,(ushort *)(local_d8 + 0x18),
                              (short *)&local_b0);
LAB_00004d0c:
          uVar3 = BfsApplyPolicyAsUser((longlong)param_4,(longlong)param_3,local_d8,lVar9,param_5);
          pdVar8 = param_4;
          uVar1 = local_e8;
          if (-1 < (int)uVar3) goto LAB_00004de8;
LAB_00004bd8:
          uVar1 = local_e8;
          local_e8 = uVar3;
          if (DAT_00016000 < 4) goto LAB_00004de8;
        }
        local_60 = &local_e8;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(pdVar8,&DAT_00013c91);
        uVar1 = local_e8;
      }
      else {
        pdVar8 = param_1;
        uVar3 = BfsGetPolicyEntry(param_1,param_2,0x16200,(byte *)*local_d0,(byte *)*local_c8,
                                  &local_e0);
        uVar1 = local_e8;
        if ((int)uVar3 < 0) {
joined_r0x00004c71:
          local_e8 = uVar3;
          lVar9 = local_e0;
          if (3 < DAT_00016000) {
            local_58 = 4;
            local_60 = &local_e8;
            _tlgWriteTransfer_EtwWriteTransfer(pdVar8,&DAT_00013c91);
            lVar9 = local_e0;
            uVar1 = local_e8;
          }
        }
        else {
          lVar7 = local_d8;
          puVar4 = BfsGetFileName(local_90,local_d8);
          lVar9 = local_e0;
          local_a0 = *(undefined8 *)puVar4;
          uStack_98 = *(undefined8 *)(puVar4 + 4);
          uVar3 = BfsGetPolicy(*(longlong *)(local_e0 + 0x30),(ushort *)(lVar7 + 0x18),&local_a0);
          if (uVar3 == 0) goto LAB_00004b82;
          if (uVar3 == 1) goto LAB_00004d0c;
          uVar1 = local_e8;
          if (uVar3 == 2) {
            uVar5 = BfsQueryAccessOnly((*(uint *)(*(longlong *)(param_4 + 4) + 0x20) & 1) + 1,
                                       (longlong)param_4);
            if ((char)uVar5 != '\0') goto LAB_00004d0c;
            uVar5 = BfsQueryAccessOnly((*(uint *)(*(longlong *)(param_4 + 4) + 0x20) & 1) + 1,
                                       (longlong)param_4);
            uVar1 = local_e8;
            if ((char)uVar5 == '\0') goto LAB_00004d3f;
          }
        }
      }
LAB_00004de8:
      local_e8 = uVar1;
      uVar1 = local_e8;
      if (lVar9 != 0) {
        BfsDereferencePolicyEntryEx(lVar9,'\0');
        uVar1 = local_e8;
      }
      goto LAB_00004df7;
    }
  }
  local_e8 = uVar3;
  if (3 < DAT_00016000) {
    local_60 = &local_e8;
    local_58 = 4;
    _tlgWriteTransfer_EtwWriteTransfer(pdVar8,&DAT_00013c91);
    uVar1 = local_e8;
  }
LAB_00004df7:
  local_e8 = uVar1;
  if (local_d8 != 0) {
    FltReleaseFileNameInformation();
  }
  if (local_d0 != (undefined8 *)0x0) {
    ExFreePoolWithTag(local_d0,0);
  }
  if (local_c8 != (undefined8 *)0x0) {
    ExFreePoolWithTag(local_c8,0);
  }
  __security_check_cookie(local_50 ^ (ulonglong)auStackY_118);
  return;
}

