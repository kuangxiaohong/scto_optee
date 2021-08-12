/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define STR_TRACE_USER_TA "SCTO"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_scto.h"
#include <string.h>

# define         EVP_CIPH_ECB_MODE               0x1
# define         EVP_CIPH_CBC_MODE               0x2
# define         EVP_CIPH_CFB_MODE               0x3
# define         EVP_CIPH_OFB_MODE               0x4
# define         EVP_CIPH_CTR_MODE               0x5
# define 		 MAX_SM4_KEY  					(128)
# define 		 MAX_SM4_IV 					(16)

//# define DEBUG (1)
typedef struct sess_ctx{
	TEE_OperationHandle op;
	uint8_t iv[MAX_SM4_IV];
}Sess_ctx_t;

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	*sess_ctx = TEE_Malloc(sizeof(Sess_ctx_t), TEE_MALLOC_FILL_ZERO);
	if(*sess_ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

#ifdef DEBUG
	EMSG("Hello World!\n");
#endif
	return TEE_SUCCESS;
}


void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;
	if (ctx && ctx->op)
	{
		TEE_FreeOperation(ctx->op);
		TEE_Free(ctx);
	}
#ifdef DEBUG
	EMSG("Goodbye!\n");
#endif
}

static void dump_meminfo(char *msg,uint8_t *data, uint64_t len)
{
#ifdef DEBUG
	EMSG("Goodbye!\n");
	if (!data)
                return ;

        uint64_t i = 0;

        EMSG("%s: %p len %u \n", msg, data, len);
        for (i = 0; i < len; i ++)
        {
                EMSG("%02x ", (uint8_t)data[i]);
                if (i%16 == 15)
                        EMSG("---%d\n", i+1);
        }
        EMSG("\n");
#endif
	return; 	
}
static TEE_Result sm4_cipher_init(Sess_ctx_t *ctx,uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
							   TEE_PARAM_TYPE_MEMREF_OUTPUT,
							   TEE_PARAM_TYPE_VALUE_INOUT,
							   TEE_PARAM_TYPE_NONE);
	
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_OperationHandle op ;
	TEE_ObjectHandle obj ; 
	TEE_Result ret = TEE_SUCCESS;

	void * key = params[0].memref.buffer;
	uint32_t keylen = params[0].memref.size;
	void * iv = params[1].memref.buffer;
	uint32_t ivlen = params[1].memref.size;

	uint32_t enc_or_dec = params[2].value.a;
	uint32_t sm4_mode = params[2].value.b;
	
	uint32_t mode = enc_or_dec ? TEE_MODE_ENCRYPT : TEE_MODE_DECRYPT;

	uint32_t algorithm;
	if ((sm4_mode & 0xf) ==  EVP_CIPH_ECB_MODE)
		algorithm = TEE_ALG_SM4_ECB_NOPAD;
	else if ((sm4_mode & 0xf) == EVP_CIPH_CBC_MODE)
		algorithm = TEE_ALG_SM4_CBC_NOPAD;
	else if ((sm4_mode & 0xf) == EVP_CIPH_CTR_MODE)
		algorithm = TEE_ALG_SM4_CTR;
		
	ret = TEE_AllocateOperation(&op, algorithm, mode, MAX_SM4_KEY);
	if(ret)
		return ret;

	ret = TEE_AllocateTransientObject(TEE_TYPE_SM4, MAX_SM4_KEY, &obj);
	if(ret)
		goto free_op;

	TEE_Attribute attrs[8] = {0};
	attrs[0].attributeID = TEE_ATTR_SECRET_VALUE;
	attrs[0].content.ref.buffer = key;
	attrs[0].content.ref.length = keylen;
	
	ret = TEE_PopulateTransientObject(obj, attrs, 1);
	if(ret)
		goto free_obj;

	ret = TEE_SetOperationKey(op, obj);
	if(ret)
		goto free_obj;

	TEE_CipherInit(op, iv, MAX_SM4_IV);
	memcpy(ctx->iv,iv,MAX_SM4_IV);
	ctx->op = op;
	dump_meminfo("sm4_cipher_init recv key",key,keylen);
	dump_meminfo("sm4_cipher_init recv iv",ctx->iv,MAX_SM4_IV);
	return ret;

free_obj:
	TEE_FreeTransientObject(obj);
free_op:
	TEE_FreeOperation(op);

}

static TEE_Result sm4_do_cipher(Sess_ctx_t *ctx,uint32_t param_types, TEE_Param params[4])
{
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_OperationHandle op = ctx->op;

	void * srcData = params[0].memref.buffer;
	uint32_t srcLen = params[0].memref.size;
	void * destData = params[1].memref.buffer;
	uint32_t destLen = params[1].memref.size;
	dump_meminfo("sm4_do_cipher recv input data",srcData,srcLen);
	TEE_Result ret = TEE_CipherUpdate(op, srcData, srcLen, destData, &destLen);
	dump_meminfo("sm4_do_cipher send result data",destData,destLen);
	if(ret)
		return ret;
	
	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_init(Sess_ctx_t *ctx,uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
							   TEE_PARAM_TYPE_NONE,
							   TEE_PARAM_TYPE_NONE,
							   TEE_PARAM_TYPE_NONE);
#ifdef DEBUG
	EMSG(" sm3_digest_init\n");
#endif

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result ret = TEE_AllocateOperation(&ctx->op, TEE_ALG_SM3, TEE_MODE_DIGEST, 0);
	if(ret)		
		return ret;
	
	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_update(Sess_ctx_t *ctx,uint32_t param_types, TEE_Param params[4])
{
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;


	void * srcData = params[0].memref.buffer;
	uint32_t srcLen = params[0].memref.size;

	dump_meminfo("sm3_digest_update recv input data",srcData,srcLen);

	TEE_DigestUpdate(ctx->op,  srcData, srcLen);
	return TEE_SUCCESS;
}

static TEE_Result sm3_digest_finish(Sess_ctx_t *ctx,uint32_t param_types, TEE_Param params[4])
{
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	void * result_buf = params[0].memref.buffer;
	uint32_t result_len = params[0].memref.size;

	if ( result_len < 32 )
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result ret = TEE_DigestDoFinal(ctx->op,	NULL, 0, result_buf, &result_len);
	dump_meminfo("sm3_digest_finish send result data",result_buf,result_len);
	
	if(ret) 	
		return ret;
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	Sess_ctx_t *ctx = (Sess_ctx_t *)sess_ctx;
	switch (cmd_id) {
		case SCTO_SM4_INIT:
			return sm4_cipher_init(ctx,param_types, params);
		case SCTO_SM4_CIPHER:
			return sm4_do_cipher(ctx,param_types, params);
		case SCTO_SM3_INIT:
			return sm3_digest_init(ctx,param_types, params);
		case SCTO_SM3_UPDATE:
			return sm3_digest_update(ctx,param_types, params);
		case SCTO_SM3_FINISH:
			return sm3_digest_finish(ctx,param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}


