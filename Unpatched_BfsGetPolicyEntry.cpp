
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void BfsGetPolicyEntry(dword *dispatchObject,undefined8 param_2,longlong sharedPushLock,byte *token_user_info_class,
                      byte *token_origin_info_class,longlong *param_6)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  longlong lVar4;
  undefined1 securityCookiePadding [32];
  longlong local_98;
  longlong policyEntryObject;
  undefined8 local_88;
  longlong *local_60;
  undefined4 local_58;
  undefined4 local_54;
  ulonglong cookie_check ;
  
  cookie_check  = __security_cookie ^ (ulonglong)securityCookiePadding;
  local_98 = 0;
  local_88 = param_2;
  uVar1 = RtlLengthSid(token_user_info_class);
  BfsUpdateHash(token_user_info_class,uVar1,&local_98);
  uVar1 = RtlLengthSid(token_origin_info_class);
  BfsUpdateHash(token_origin_info_class,uVar1,&local_98);
  uVar3 = BfsFinalHash(&local_98);
  *param_6 = 0;
  KeEnterCriticalRegion();
  ExAcquirePushLockSharedEx(sharedPushLock,0);
  lVar4 = BfsLookupPolicyEntryHashTable(*(undefined8 *)(sharedPushLock + 8),uVar3,token_user_info_class,token_origin_info_class);
  policyEntryObject = lVar4;
  if ((lVar4 == 0) || ((*(uint *)(lVar4 + 0x38) & 0x10000000) == 0)) {
    ExReleasePushLockSharedEx(sharedPushLock,0);
    KeLeaveCriticalRegion();
    iVar2 = BfsInsertPolicyEntry
                      (dispatchObject,local_88,sharedPushLock,uVar3,(longlong)token_user_info_class,(longlong)token_origin_info_class,&policyEntryObject)
    ;
    if (iVar2 < 0) {
      if (3 < .data) {
        local_98 = CONCAT44(local_98._4_4_,iVar2);
LAB_00005f7f:
        local_54 = 0;
        local_60 = &local_98;
        local_58 = 4;
        _tlgWriteTransfer_EtwWriteTransfer(dispatchObject,&DAT_00013c91);
      }
LAB_00005fa7:
      if (policyEntryObject != 0) {
        BfsDereferencePolicyEntryEx(policyEntryObject,'\0');
      }
      goto LAB_00005fd5;
    }
  }
  else {
    LOCK();
    *(int *)(lVar4 + 0x90) = *(int *)(lVar4 + 0x90) + 1;
    UNLOCK();
    ExReleasePushLockSharedEx(sharedPushLock);
    KeLeaveCriticalRegion();
    if (*(int *)(lVar4 + 0x38) == 0x10000001) {
      dispatchObject = *(dword **)(lVar4 + 0x28);
      KeWaitForSingleObject(dispatchObject,0,0,0);
      if (*(int *)(lVar4 + 0x38) != 0x10000000) {
        if (3 < .data) {
          local_98 = CONCAT44(local_98._4_4_,0xc0000001);
          goto LAB_00005f7f;
        }
        goto LAB_00005fa7;
      }
    }
  }
  LOCK();
  *(undefined8 *)(policyEntryObject + 0x60) = _DAT_fffff78000000014;
  UNLOCK();
  *param_6 = policyEntryObject;
LAB_00005fd5:
  __security_check_cookie(cookie_check  ^ (ulonglong)securityCookiePadding);
  return;
}

