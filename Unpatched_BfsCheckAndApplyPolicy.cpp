
void BfsCheckAndApplyPolicy
               (dword *param_1,longlong param_2,dword *access_token,dword *flt_callback_data,
               longlong *param_5)

{
  uint statusCode_garbage_collector;
  byte isBfsEntryExist;
  uint nt_status_var1;
  ushort *file_name;
  undefined8 bfs_func_status;
  longlong PolicyEntry;
  undefined1 securityCookiePadding [32];
  uint statusCode_garbage;
  char isTokenCapable;
  char local_e3 [3];
  longlong deferredPolicyEntry;
  longlong file_name_info;
  PVOID *token_user_info_class;
  PVOID *token_origin_info_class;
  dword *tempAccessToken;
  longlong deferredFileNameInfo;
  undefined8 local_b0;
  undefined8 garbage_variable_1;
  undefined8 local_a0;
  undefined8 filename_buffer;
  ushort file_name_unicode_array [24];
  uint *statusCode_garbage_collector_2;
  undefined8 etw_write_related_code;
  ulonglong cookie_check;
  longlong fileNameInfo_local_var;
  dword *temp_saver_pointer;
  
  cookie_check = __security_cookie ^ (ulonglong)securityCookiePadding;
  local_e3[0] = '\0';
  token_user_info_class = (PVOID *)0x0;
  deferredPolicyEntry = 0;
  file_name_info = 0;
  token_origin_info_class = (PVOID *)0x0;
  local_b0 = 0;
  garbage_variable_1 = 0;
  temp_saver_pointer = access_token;
  nt_status_var1 = SeQueryInformationToken(access_token,1,&token_user_info_class);
  statusCode_garbage_collector = statusCode_garbage;
  if ((-1 < (int)nt_status_var1) &&
     (temp_saver_pointer = access_token,
     nt_status_var1 = SeQueryInformationToken(access_token,0x1f,&token_origin_info_class),
     statusCode_garbage_collector = statusCode_garbage, -1 < (int)nt_status_var1)) {
    nt_status_var1 = FltGetFileNameInformation(flt_callback_data,0x101,&file_name_info);
    if (nt_status_var1 == 0xc0000201) {
      deferredFileNameInfo = 0;
      tempAccessToken = access_token;
      nt_status_var1 =
           BfsQueueDeferredWorkItemAndWait
                     ((longlong)param_1,param_2,flt_callback_data,&tempAccessToken,
                      BfsQueryFileNameInformationCallback);
      file_name_info = deferredFileNameInfo;
    }
    temp_saver_pointer = (dword *)(ulonglong)nt_status_var1;
    statusCode_garbage_collector = statusCode_garbage;
    if (-1 < (int)nt_status_var1) {
      isBfsEntryExist =
           BfsPolicyEntryExists
                     (param_1,param_2,0x16200,(byte *)*token_user_info_class,
                      (byte *)*token_origin_info_class);
      if (isBfsEntryExist == 0) {
        temp_saver_pointer = (dword *)&gBfsPolicyTable;
        bfs_func_status = BfsGetNotPresentPolicyEntry
                          (0x16200,(byte *)*token_user_info_class,(byte *)*token_origin_info_class,
                           &deferredPolicyEntry);
        PolicyEntry = deferredPolicyEntry;
        nt_status_var1 = (uint)bfs_func_status;
        statusCode_garbage_collector = statusCode_garbage;
        if ((int)(uint)bfs_func_status < 0) goto joined_r0x00004c71;
LAB_00004b82:
        isTokenCapable = '\0';
        temp_saver_pointer = (dword *)0x0;
        nt_status_var1 =
             RtlCheckTokenCapability
                       (0,*(undefined8 *)(*(longlong *)SeExports_exref + 0x250),&isTokenCapable);
        if ((int)nt_status_var1 < 0) {
          if (nt_status_var1 != 0xc0000022) goto LAB_00004bd8;
LAB_00004ceb:
          if ((file_name_info == 0) &&
             (nt_status_var1 = FltGetFileNameInformation(flt_callback_data,0x101,&file_name_info),
             temp_saver_pointer = flt_callback_data, (int)nt_status_var1 < 0)) goto LAB_00004bd8;
          fileNameInfo_local_var = *param_5;
          if (fileNameInfo_local_var != 0) {
LAB_00004d54:
            *(undefined4 *)(fileNameInfo_local_var + 8) = 1;
            FltReferenceFileNameInformation(file_name_info);
            *(longlong *)(*param_5 + 0x30) = file_name_info;
            *(longlong *)(*param_5 + 0x40) = PolicyEntry;
            LOCK();
            *(int *)(PolicyEntry + 0x90) = *(int *)(PolicyEntry + 0x90) + 1;
            UNLOCK();
            *(uint *)*param_5 = *(uint *)*param_5 | 1;
            PolicyEntry = deferredPolicyEntry;
            statusCode_garbage_collector = statusCode_garbage;
            goto LAB_00004d94;
          }
          temp_saver_pointer = &IMAGE_NT_HEADERS64_000000f0.FileHeader.NumberOfSymbols;
          fileNameInfo_local_var = ExAllocatePool2(0x100,0x58,0x43736642);
          *param_5 = fileNameInfo_local_var;
          if (fileNameInfo_local_var != 0) goto LAB_00004d54;
          statusCode_garbage_collector = statusCode_garbage;
          if (.data < 4) goto LAB_00004d94;
          statusCode_garbage = 0xc0000017;
        }
        else {
          if (isTokenCapable == '\0') goto LAB_00004ceb;
          temp_saver_pointer = access_token;
          nt_status_var1 =
               BfsFileInPublisherDirectory(access_token,file_name_info,(ushort *)local_e3,&local_b0)
          ;
          if ((int)nt_status_var1 < 0) goto LAB_00004bd8;
          if (local_e3[0] == '\0') goto LAB_00004ceb;
          if (PolicyEntry == 0) {
LAB_00004c37:
            nt_status_var1 =
                 BfsGetPolicyEntry(param_1,param_2,0x16200,(byte *)*token_user_info_class,
                                   (byte *)*token_origin_info_class,&deferredPolicyEntry);
            PolicyEntry = deferredPolicyEntry;
            temp_saver_pointer = param_1;
            statusCode_garbage_collector = statusCode_garbage;
            if ((int)nt_status_var1 < 0) goto joined_r0x00004c71;
          }
          else if (*(int *)(PolicyEntry + 0x38) == 2) {
            BfsDereferencePolicyEntryEx(PolicyEntry,'\0');
            goto LAB_00004c37;
          }
          BfsAddOrModifyEntry(*(longlong *)(PolicyEntry + 0x30),2,1,2,
                              (ushort *)(file_name_info + 0x18),(short *)&local_b0);
LAB_00004cb8:
          nt_status_var1 =
               BfsApplyPolicyAsUser
                         ((longlong)flt_callback_data,(longlong)access_token,file_name_info,
                          PolicyEntry,param_5);
          temp_saver_pointer = flt_callback_data;
          statusCode_garbage_collector = statusCode_garbage;
          if (-1 < (int)nt_status_var1) goto LAB_00004d94;
LAB_00004bd8:
          statusCode_garbage_collector = statusCode_garbage;
          statusCode_garbage = nt_status_var1;
          if (.data < 4) goto LAB_00004d94;
        }
        statusCode_garbage_collector_2 = &statusCode_garbage;
        etw_write_related_code = 4;
        _tlgWriteTransfer_EtwWriteTransfer(temp_saver_pointer,&DAT_00013c91);
        statusCode_garbage_collector = statusCode_garbage;
      }
      else {
        temp_saver_pointer = param_1;
        nt_status_var1 =
             BfsGetPolicyEntry(param_1,param_2,0x16200,(byte *)*token_user_info_class,
                               (byte *)*token_origin_info_class,&deferredPolicyEntry);
        statusCode_garbage_collector = statusCode_garbage;
        if ((int)nt_status_var1 < 0) {
joined_r0x00004c71:
          statusCode_garbage = nt_status_var1;
          PolicyEntry = deferredPolicyEntry;
          if (3 < .data) {
            etw_write_related_code = 4;
            statusCode_garbage_collector_2 = &statusCode_garbage;
            _tlgWriteTransfer_EtwWriteTransfer(temp_saver_pointer,&DAT_00013c91);
            PolicyEntry = deferredPolicyEntry;
            statusCode_garbage_collector = statusCode_garbage;
          }
        }
        else {
          fileNameInfo_local_var = file_name_info;
          file_name = BfsGetFileName(file_name_unicode_array,file_name_info);
          PolicyEntry = deferredPolicyEntry;
          local_a0 = *(undefined8 *)file_name;
          filename_buffer = *(undefined8 *)(file_name + 4);
          nt_status_var1 =
               BfsGetPolicy(*(longlong *)(deferredPolicyEntry + 0x30),
                            (ushort *)(fileNameInfo_local_var + 0x18),&local_a0);
          if (nt_status_var1 == 0) goto LAB_00004b82;
          if (nt_status_var1 == 1) goto LAB_00004cb8;
          statusCode_garbage_collector = statusCode_garbage;
          if (nt_status_var1 == 2) {
            bfs_func_status = BfsQueryAccessOnly((*(uint *)(*(longlong *)(flt_callback_data + 4) + 0x20) & 1)
                                       + 1,(longlong)flt_callback_data);
            if ((char)bfs_func_status != '\0') goto LAB_00004cb8;
            bfs_func_status = BfsQueryAccessOnly((*(uint *)(*(longlong *)(flt_callback_data + 4) + 0x20) & 1)
                                       + 1,(longlong)flt_callback_data);
            statusCode_garbage_collector = statusCode_garbage;
            if ((char)bfs_func_status == '\0') goto LAB_00004ceb;
          }
        }
      }
LAB_00004d94:
      statusCode_garbage = statusCode_garbage_collector;
      statusCode_garbage_collector = statusCode_garbage;
      if (PolicyEntry != 0) {
        BfsDereferencePolicyEntryEx(PolicyEntry,'\0');
        statusCode_garbage_collector = statusCode_garbage;
      }
      goto LAB_00004da3;
    }
  }
  statusCode_garbage = nt_status_var1;
  if (3 < .data) {
    statusCode_garbage_collector_2 = &statusCode_garbage;
    etw_write_related_code = 4;
    _tlgWriteTransfer_EtwWriteTransfer(temp_saver_pointer,&DAT_00013c91);
    statusCode_garbage_collector = statusCode_garbage;
  }
LAB_00004da3:
  statusCode_garbage = statusCode_garbage_collector;
  if (file_name_info != 0) {
    FltReleaseFileNameInformation();
  }
  if (token_user_info_class != (PVOID *)0x0) {
    ExFreePoolWithTag(token_user_info_class,0);
  }
  if (token_origin_info_class != (PVOID *)0x0) {
    ExFreePoolWithTag(token_origin_info_class,0);
  }
  __security_check_cookie(cookie_check ^ (ulonglong)securityCookiePadding);
  return;
}

