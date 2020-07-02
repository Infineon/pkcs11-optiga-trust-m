#include "optiga/optiga_crypt.h"
#include "optiga/cmd/optiga_cmd.h"
#include "optiga/common/optiga_lib_logger.h"
#include "optiga/pal/pal_os_memory.h"
#include "c_unit_helper.h"




/* 
 * Invoking _optiga_crypt_hash_start API all possible scenario 
*/
void ut_optiga_pksc11_test_001()
{
 /* 
   * 1.  crypt as NULL
   */
	/*
	 * a. Initialize test variables
	 */     
   
	optiga_lib_status_t return_status = 1;
	optiga_crypt_t * p_optiga_crypt = NULL;

	/* 
	* b. Initialize stub Variable here 
	*/
	
	/*
	 * c. Test Execution
	 */
	
	/* 
	 * d. Test asserts 
	 */
	CU_ASSERT_EQUAL( return_status, 1);
 
}

