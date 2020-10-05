#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"
#include "c_unit_helper.h"


void st_c_test_get_mechanism_info_valid_001(void)
{
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
    CK_MECHANISM_INFO mechanism_info = { 0 };
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
			
			rv = function_list->C_GetMechanismInfo( pSlotList[ 0 ], CKM_RSA_PKCS, &mechanism_info );
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetMechanismInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			CU_ASSERT_EQUAL( mechanism_info.flags, (CKF_SIGN | CKF_VERIFY | CKA_ENCRYPT | CKA_DECRYPT) );
			CU_ASSERT_EQUAL( mechanism_info.ulMaxKeySize, 2048 );
			CU_ASSERT_EQUAL( mechanism_info.ulMinKeySize, 1024 );
			
			memset(&mechanism_info,0, sizeof(mechanism_info));
			
			rv = function_list->C_GetMechanismInfo( pSlotList[ 0 ], CKM_ECDSA, &mechanism_info );
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetMechanismInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			CU_ASSERT_EQUAL( mechanism_info.flags, (CKF_SIGN | CKF_VERIFY ) );
			CU_ASSERT_EQUAL( mechanism_info.ulMaxKeySize, 521 );
			CU_ASSERT_EQUAL( mechanism_info.ulMinKeySize, 256 );
			
			memset(&mechanism_info,0, sizeof(mechanism_info));
			
			rv = function_list->C_GetMechanismInfo( pSlotList[ 0 ], CKM_EC_KEY_PAIR_GEN, &mechanism_info );
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetMechanismInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			CU_ASSERT_EQUAL( mechanism_info.flags, CKF_GENERATE_KEY_PAIR );
			CU_ASSERT_EQUAL( mechanism_info.ulMaxKeySize, 521 );
			CU_ASSERT_EQUAL( mechanism_info.ulMinKeySize, 256 );
			
			memset(&mechanism_info,0, sizeof(mechanism_info));
			rv = function_list->C_GetMechanismInfo( pSlotList[ 0 ], CKM_RSA_PKCS_KEY_PAIR_GEN, &mechanism_info );
			CU_ASSERT_EQUAL( CKR_OK, rv );	
			if (rv != CKR_OK) 
			{
				printf("C_GetMechanismInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}
			CU_ASSERT_EQUAL( mechanism_info.flags, CKF_GENERATE_KEY_PAIR );
			CU_ASSERT_EQUAL( mechanism_info.ulMaxKeySize, 2048 );
			CU_ASSERT_EQUAL( mechanism_info.ulMinKeySize, 1024 );
		}
		
	}while (0);
	
		if (NULL != pSlotList)
		{
			free(pSlotList);
		}
}

void st_c_test_get_mechanism_info_invalid_type_002(void)
{
	CK_ULONG ulCount;
	CK_SLOT_ID_PTR pSlotList;
	CK_SLOT_INFO slotInfo;
    CK_MECHANISM_INFO mechanism_info = { 0 };
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
			
			rv = function_list->C_GetMechanismInfo( pSlotList[ 0 ], CKM_SHA384, &mechanism_info );
			CU_ASSERT_EQUAL( CKR_MECHANISM_INVALID, rv );	
			if (rv != CKR_MECHANISM_INVALID) 
			{
				printf("C_GetMechanismInfo failed with Response Code :%x at line Number : %d\n",rv, __LINE__);
				break;		
			}

		}
		
	}while (0);
	
		if (NULL != pSlotList)
		{
			free(pSlotList);
		}
}
