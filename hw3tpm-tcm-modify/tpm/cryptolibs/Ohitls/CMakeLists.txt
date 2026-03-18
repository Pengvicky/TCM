project(Tpm_Cryptolib_Ohitls VERSION 1.0)

add_library(Tpm_CryptoLib_Math_Ohitls STATIC)
add_library(Tpm_CryptoLib_Math_Ohitls::Tpm_CryptoLib_Math_Ohitls ALIAS Tpm_CryptoLib_Math_Ohitls)
add_library(Tpm_CryptoLib_Symmetric_Ohitls ALIAS Tpm_CryptoLib_Math_Ohitls)
add_library(Tpm_CryptoLib_Hash_Ohitls ALIAS Tpm_CryptoLib_Math_Ohitls)

target_link_libraries(Tpm_CryptoLib_Math_Ohitls PUBLIC TpmConfiguration)
target_link_libraries(Tpm_CryptoLib_Math_Ohitls PUBLIC Tpm_Public_Headers)
target_link_libraries(Tpm_CryptoLib_Math_Ohitls PUBLIC Tpm_CryptoLib_TpmBigNum_Headers)

# include directories similar to Ossl variant
target_include_directories(Tpm_CryptoLib_Math_Ohitls PRIVATE
    ../../include
)

target_sources(Tpm_CryptoLib_Math_Ohitls PRIVATE
    "TpmToOhitlsMath.c"
    "TpmToOhitlsSupport.c"
    "TpmToOhitlsSym.c"
)

target_include_directories(Tpm_CryptoLib_Math_Ohitls PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

install_and_export_config_targets(Tpm_CryptoLib_Math_Ohitls)
