#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11_optiga_trustm.h"
#include "c_unit_helper.h"


void st_c_test_tokeninfo_valid_001(void)
{
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;	
	do
	{
		rv = C_GetFunctionList( &function_list );
		CU_ASSERT_EQUAL( CKR_OK, rv );
		if( rv != CKR_OK )
		{
			printf("C_GetFunctionList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;
		}	
		rv = function_list->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
		if ((rv == CKR_OK) && (ulCount > 0)) 
		{
			pSlotList = (CK_SLOT_ID_PTR) malloc(ulCount*sizeof(CK_SLOT_ID));
			
			rv = function_list->C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetSlotList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			/* Get slot information for first slot */
			rv = function_list->C_GetTokenInfo(pSlotList[0], &tokenInfo);
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetTokenInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			CU_ASSERT_EQUAL( tokenInfo.firmwareVersion.major, 0x2 );
			CU_ASSERT_EQUAL( tokenInfo.firmwareVersion.minor, 0x28 );
			CU_ASSERT_EQUAL( tokenInfo.hardwareVersion.major, 0x1 );
			CU_ASSERT_EQUAL( tokenInfo.hardwareVersion.minor, 0 );
			CU_ASSERT_STRING_EQUAL(tokenInfo.manufacturerID, "Infineon Technologies AG");
			CU_ASSERT_STRING_EQUAL(tokenInfo.model, "OPTIGA Trust M");
			CU_ASSERT_EQUAL( tokenInfo.ulMaxSessionCount, 4 );
		}
		
	}while (0);
	
		if (NULL != pSlotList)
		{
			free(pSlotList);
		}
}

void st_c_test_tokeninfo_invalid_slot_002(void)
{
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;	
	do
	{
		rv = C_GetFunctionList( &function_list );
		CU_ASSERT_EQUAL( CKR_OK, rv );
		if( rv != CKR_OK )
		{
			printf("C_GetFunctionList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;
		}	
		rv = function_list->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
		if ((rv == CKR_OK) && (ulCount > 0)) 
		{
			pSlotList = (CK_SLOT_ID_PTR) malloc(ulCount*sizeof(CK_SLOT_ID));
			
			rv = function_list->C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetSlotList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			/* Get slot information for first slot */
			rv = function_list->C_GetTokenInfo(2, &tokenInfo);
			CU_ASSERT_EQUAL( CKR_SLOT_ID_INVALID, rv );	
			if (rv != CKR_SLOT_ID_INVALID) 
			{
				printf("C_GetTokenInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}

		}
		
	}while (0);
	
		if (NULL != pSlotList)
		{
			free(pSlotList);
		}
}

void st_c_test_tokeninfo_null_pointer_003(void)
{
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
	CK_TOKEN_INFO tokenInfo;
	CK_RV rv;
	CK_FUNCTION_LIST_PTR function_list;	
	do
	{
		rv = C_GetFunctionList( &function_list );
		CU_ASSERT_EQUAL( CKR_OK, rv );
		if( rv != CKR_OK )
		{
			printf("C_GetFunctionList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
			break;
		}	
		rv = function_list->C_GetSlotList(CK_FALSE, NULL_PTR, &ulCount);
		if ((rv == CKR_OK) && (ulCount > 0)) 
		{
			pSlotList = (CK_SLOT_ID_PTR) malloc(ulCount*sizeof(CK_SLOT_ID));
			
			rv = function_list->C_GetSlotList(CK_FALSE, pSlotList, &ulCount);
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetSlotList failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			/* Get slot information for first slot */
			rv = function_list->C_GetTokenInfo(pSlotList[0], NULL);
			CU_ASSERT_EQUAL( CKR_ARGUMENTS_BAD, rv );	
			if (rv != CKR_ARGUMENTS_BAD) 
			{
				printf("C_GetTokenInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}

		}
		
	}while (0);
	
		if (NULL != pSlotList)
		{
			free(pSlotList);
		}
}
