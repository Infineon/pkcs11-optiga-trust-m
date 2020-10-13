#include "c_unit_helper.h"
/////////////////////include test cases prototyping here/////////////////////
//function prototyping

//Cmd Lib:Get Data
INCLUDE(test_c_init_args)
INCLUDE(st_c_initialize_finalize_valid_001)
INCLUDE(st_c_initialize_invalid_002)
INCLUDE(st_c_finalize_invalid_003)

INCLUDE(st_c_generate_random_valid_001)
INCLUDE(st_c_generate_random_invalid_002)
INCLUDE(st_c_generate_random_invalid_003)

INCLUDE(st_c_generate_keypair_ecc_p_256_valid_001)
INCLUDE(st_c_generate_keypair_ecc_p_384_valid_002)
INCLUDE(st_c_generate_keypair_ecc_p_521_valid_003)
INCLUDE(st_c_generate_keypair_ecc_invalid_004)
INCLUDE(st_c_generate_keypair_ecc_invalid_missing_attribute_005)

INCLUDE(st_c_generate_keypair_rsa_1024_valid_001)
INCLUDE(st_c_generate_keypair_rsa_2048_valid_002)
INCLUDE(st_c_generate_keypair_rsa_1024_invalid_003)
INCLUDE(st_c_generate_keypair_rsa_1024_invalid_missing_attribute_004)

INCLUDE(st_c_sign_ecc_valid_001)
INCLUDE(st_c_sign_ecc_384_valid_001)
INCLUDE(st_c_sign_ecc_521_valid_003)
INCLUDE(st_c_sign_ecc_invalid_no_signinit_002)
INCLUDE(st_c_sign_ecc_invalid_buffer_small_003)
INCLUDE(st_c_sign_rsa_1024_valid_001)
INCLUDE(st_c_sign_rsa_2048_valid_002)
INCLUDE(st_c_sign_rsa_1024_valid_different_sign_scheme_003)
INCLUDE(st_c_sign_rsa_1024_invalid_no_sign_init_004)
INCLUDE(st_c_sign_rsa_1024_invalid_buffer_small_005)

INCLUDE(st_c_verify_ecc_valid_001)
INCLUDE(st_c_verify_ecc_invalid_no_verifyinit_002)
INCLUDE(st_c_verify_ecc_invalid_sign_len_invalid_003)
INCLUDE(st_c_verify_ecc_invalid_sign_invalid_004)
INCLUDE(st_c_verify_rsa_1024_valid_001)
INCLUDE(st_c_verify_rsa_2048_valid_002)
INCLUDE(st_c_verify_rsa_1024_invalid_no_verify_init_003)
INCLUDE(st_c_verify_rsa_1024_invalid_sign_invalid_004)

INCLUDE(st_c_encrypt_decrypt_rsa_1024_valid_001)
INCLUDE(st_c_encrypt_decrypt_rsa_2048_valid_002)
INCLUDE(st_c_encrypt_init_ck_encrypt_false_invalid_003)
INCLUDE(st_c_encrypt_rsa_1024_invalid_without_init_004)
INCLUDE(st_c_decrypt_rsa_1024_invalid_without_init_005)
INCLUDE(st_c_encrypt_rsa_1024_invalid_buffer_low_006)
INCLUDE(st_c_decrypt_init_ck_decrypt_false_invalid_007)
INCLUDE(st_c_encrypt_decrypt_rsa_1024_invalid_len_range_008)

INCLUDE(st_c_digest_init_update_final_valid_001)
INCLUDE(st_c_digest_update_final_invalid_002)
INCLUDE(st_c_digest_init_update_final_invalid_buffer_small_003)
INCLUDE(st_c_digest_init_mechanism_invalid_004)
INCLUDE(st_c_digest_init_update_final_terminates_valid_005)
INCLUDE(st_c_digest_init_operation_active_invalid_006)

INCLUDE(st_c_test_tokeninfo_valid_001)
INCLUDE(st_c_test_tokeninfo_invalid_slot_002)
INCLUDE(st_c_test_tokeninfo_null_pointer_003)

INCLUDE(st_c_test_get_mechanism_info_valid_001)
INCLUDE(st_c_test_get_mechanism_info_invalid_type_002)

INCLUDE(st_c_get_attribute_value_valid_001)
INCLUDE(st_c_get_attribute_value_invalid_002)

INCLUDE(st_c_test_find_objects_info_valid_001)
INCLUDE(st_c_test_find_objects_init_invalid_002)
INCLUDE(st_c_test_find_objects_invalid_003)


//not built file were, None
void make_it_fail()
{
	CU_FAIL("All test in this exe need to be modified due to async and optiga changes");
}
//creates suites
int CreateTestSuite(int (*fptrCUHelper)(sTestSuite_d*,int))
{
	int status = 0;
	do
	{
		/////////////////////Add test cases in respective suites/////////////////////
		START_SUITE(optiga_pkcs_11_system_test_cases)//name of the suite

			ADDTEST(st_c_initialize_finalize_valid_001)
			ADDTEST(st_c_initialize_invalid_002)
			ADDTEST(st_c_finalize_invalid_003)
			
			ADDTEST(st_c_generate_random_valid_001)
			ADDTEST(st_c_generate_random_invalid_002)
			ADDTEST(st_c_generate_random_invalid_003)
			
			ADDTEST(st_c_generate_keypair_ecc_p_256_valid_001)
			ADDTEST(st_c_generate_keypair_ecc_p_384_valid_002)
			ADDTEST(st_c_generate_keypair_ecc_p_521_valid_003)			
			ADDTEST(st_c_generate_keypair_ecc_invalid_004)
			ADDTEST(st_c_generate_keypair_ecc_invalid_missing_attribute_005)
			ADDTEST(st_c_generate_keypair_rsa_1024_valid_001)
			ADDTEST(st_c_generate_keypair_rsa_2048_valid_002)
			ADDTEST(st_c_generate_keypair_rsa_1024_invalid_003)
			ADDTEST(st_c_generate_keypair_rsa_1024_invalid_missing_attribute_004)

			ADDTEST(st_c_sign_ecc_valid_001)
			ADDTEST(st_c_sign_ecc_384_valid_001)
			ADDTEST(st_c_sign_ecc_521_valid_003)
			ADDTEST(st_c_sign_ecc_invalid_no_signinit_002)
			ADDTEST(st_c_sign_ecc_invalid_buffer_small_003)
			ADDTEST(st_c_sign_rsa_1024_valid_001)
			ADDTEST(st_c_sign_rsa_2048_valid_002)
			ADDTEST(st_c_sign_rsa_1024_valid_different_sign_scheme_003)
			ADDTEST(st_c_sign_rsa_1024_invalid_no_sign_init_004)
			ADDTEST(st_c_sign_rsa_1024_invalid_buffer_small_005)
			
			ADDTEST(st_c_verify_ecc_valid_001)
			ADDTEST(st_c_verify_ecc_invalid_no_verifyinit_002)
			ADDTEST(st_c_verify_ecc_invalid_sign_len_invalid_003)
			ADDTEST(st_c_verify_ecc_invalid_sign_invalid_004)
			ADDTEST(st_c_verify_rsa_1024_valid_001)
			ADDTEST(st_c_verify_rsa_2048_valid_002)
			ADDTEST(st_c_verify_rsa_1024_invalid_no_verify_init_003)
			ADDTEST(st_c_verify_rsa_1024_invalid_sign_invalid_004)
			
			ADDTEST(st_c_encrypt_decrypt_rsa_1024_valid_001)
			ADDTEST(st_c_encrypt_decrypt_rsa_2048_valid_002)
			ADDTEST(st_c_encrypt_init_ck_encrypt_false_invalid_003)		
			ADDTEST(st_c_encrypt_rsa_1024_invalid_without_init_004)
			ADDTEST(st_c_decrypt_rsa_1024_invalid_without_init_005)	
			ADDTEST(st_c_encrypt_rsa_1024_invalid_buffer_low_006)
			ADDTEST(st_c_decrypt_init_ck_decrypt_false_invalid_007)
			ADDTEST(st_c_encrypt_decrypt_rsa_1024_invalid_len_range_008)

			ADDTEST(st_c_digest_init_update_final_valid_001)
			ADDTEST(st_c_digest_update_final_invalid_002)
			ADDTEST(st_c_digest_init_update_final_invalid_buffer_small_003)
			ADDTEST(st_c_digest_init_mechanism_invalid_004)
			ADDTEST(st_c_digest_init_update_final_terminates_valid_005)
			// Below test case commented out and will be discussed with Artem
			//ADDTEST(st_c_digest_init_operation_active_invalid_006)
			
			ADDTEST(st_c_test_tokeninfo_valid_001)
		    ADDTEST(st_c_test_tokeninfo_invalid_slot_002)
			ADDTEST(st_c_test_tokeninfo_null_pointer_003)
			
			ADDTEST(st_c_test_get_mechanism_info_valid_001)
			ADDTEST(st_c_test_get_mechanism_info_invalid_type_002)	

		    ADDTEST(st_c_get_attribute_value_valid_001)
		    ADDTEST(st_c_get_attribute_value_invalid_002)			

			ADDTEST(st_c_test_find_objects_info_valid_001)
			ADDTEST(st_c_test_find_objects_init_invalid_002)
			ADDTEST(st_c_test_find_objects_invalid_003)

        END_SUITE
        
		/////////////////////////////////////////////////////////////////////////////
		/////////////////////////////Add new test suites/////////////////////////////
		//include suite here
		sTestSuite_d setOfSuitesTB[]=
		{
			ADDSUITE(optiga_pkcs_11_system_test_cases)
		};
		/////////////////////////////////////////////////////////////////////////////

		//call cunit helper to add suites to registry
		status = fptrCUHelper(setOfSuitesTB,sizeof(setOfSuitesTB)/sizeof(sTestSuite_d));
	}while(0);

	return status;
}


