add_library(hacl "")

target_sources(hacl
	PRIVATE
		Hacl_Curve25519_51.c
		Hacl_Kremlib.c
		Hacl_SHA3.c
		Lib_Memzero0.c
		Lib_RandomBuffer_System.c
		
		callconv.h
		compat.h
		evercrypt_targetconfig.h
		fstar_uint128_gcc64.h
		FStar_UInt128.h
		fstar_uint128_struct_endianness.h
		FStar_UInt128_Verified.h
		FStar_UInt_8_16_32_64.h
		Hacl_Curve25519_51.h
		Hacl_Kremlib.h
		Hacl_SHA3.h
		libintvector.h
		Lib_Memzero0.h
		Lib_RandomBuffer_System.h
		lowstar_endianness.h
		LowStar_Endianness.h
		target.h
		types.h
)

