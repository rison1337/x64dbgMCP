#include "file_identity.hpp"

#ifdef _WIN32

#include "launch_core.hpp"

#include <bcrypt.h>

#include <algorithm>
#include <limits>
#include <vector>

namespace mcplaunch
{
    namespace
    {
        struct AlgorithmHandle
        {
            BCRYPT_ALG_HANDLE value = nullptr;
            ~AlgorithmHandle()
            {
                if(value)
                    BCryptCloseAlgorithmProvider(value, 0);
            }
        };

        struct HashHandle
        {
            BCRYPT_HASH_HANDLE value = nullptr;
            ~HashHandle()
            {
                if(value)
                    BCryptDestroyHash(value);
            }
        };

        std::string hexLower(const uint8_t* data, size_t size)
        {
            static constexpr char digits[] = "0123456789abcdef";
            std::string result(size * 2, '\0');
            for(size_t index = 0; index < size; ++index)
            {
                result[index * 2] = digits[data[index] >> 4];
                result[index * 2 + 1] = digits[data[index] & 0x0f];
            }
            return result;
        }

        bool queryFinalPath(HANDLE handle,
                            std::wstring& path,
                            DWORD& error)
        {
            error = ERROR_SUCCESS;
            DWORD required = GetFinalPathNameByHandleW(
                handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if(required == 0)
            {
                error = GetLastError();
                return false;
            }
            std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1u,
                                        L'\0');
            const DWORD written = GetFinalPathNameByHandleW(
                handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            if(written == 0 || written >= buffer.size())
            {
                error = written == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
                return false;
            }
            path.assign(buffer.data(), written);
            return true;
        }

        UniqueHandle reopenForIdentity(HANDLE source,
                                       const std::wstring& finalPath,
                                       DWORD& error)
        {
            HANDLE reopened = ReOpenFile(
                source, GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_SEQUENTIAL_SCAN);
            if(isValidHandle(reopened))
            {
                error = ERROR_SUCCESS;
                return UniqueHandle(reopened);
            }
            error = GetLastError();
            if(finalPath.empty())
                return {};
            reopened = CreateFileW(
                finalPath.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if(!isValidHandle(reopened))
            {
                error = GetLastError();
                return {};
            }
            error = ERROR_SUCCESS;
            return UniqueHandle(reopened);
        }

        bool sha256Handle(HANDLE handle,
                          std::string& digest,
                          DWORD& win32Error,
                          std::string& errorCode,
                          std::string& error)
        {
            AlgorithmHandle algorithm;
            NTSTATUS status = BCryptOpenAlgorithmProvider(
                &algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
            if(status < 0)
            {
                win32Error = ERROR_GEN_FAILURE;
                errorCode = "sha256_provider_failed";
                error = "BCryptOpenAlgorithmProvider(SHA-256) failed";
                return false;
            }
            DWORD objectBytes = 0;
            DWORD hashBytes = 0;
            DWORD copied = 0;
            status = BCryptGetProperty(
                algorithm.value, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes),
                &copied, 0);
            if(status < 0 || objectBytes == 0)
            {
                win32Error = ERROR_GEN_FAILURE;
                errorCode = "sha256_property_failed";
                error = "BCrypt SHA-256 object length is unavailable";
                return false;
            }
            status = BCryptGetProperty(
                algorithm.value, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(&hashBytes), sizeof(hashBytes),
                &copied, 0);
            if(status < 0 || hashBytes != 32)
            {
                win32Error = ERROR_GEN_FAILURE;
                errorCode = "sha256_property_failed";
                error = "BCrypt SHA-256 hash length is invalid";
                return false;
            }
            std::vector<uint8_t> object(objectBytes);
            HashHandle hash;
            status = BCryptCreateHash(
                algorithm.value, &hash.value, object.data(), objectBytes,
                nullptr, 0, 0);
            if(status < 0)
            {
                win32Error = ERROR_GEN_FAILURE;
                errorCode = "sha256_create_failed";
                error = "BCryptCreateHash failed";
                return false;
            }

            std::vector<uint8_t> buffer(1u << 20);
            while(true)
            {
                DWORD read = 0;
                if(!ReadFile(handle, buffer.data(),
                             static_cast<DWORD>(buffer.size()), &read, nullptr))
                {
                    win32Error = GetLastError();
                    errorCode = "sha256_read_failed";
                    error = "ReadFile failed while hashing the image";
                    return false;
                }
                if(read == 0)
                    break;
                status = BCryptHashData(hash.value, buffer.data(), read, 0);
                if(status < 0)
                {
                    win32Error = ERROR_GEN_FAILURE;
                    errorCode = "sha256_update_failed";
                    error = "BCryptHashData failed";
                    return false;
                }
            }
            std::array<uint8_t, 32> bytes{};
            status = BCryptFinishHash(hash.value, bytes.data(),
                                      static_cast<ULONG>(bytes.size()), 0);
            if(status < 0)
            {
                win32Error = ERROR_GEN_FAILURE;
                errorCode = "sha256_finish_failed";
                error = "BCryptFinishHash failed";
                return false;
            }
            digest = hexLower(bytes.data(), bytes.size());
            return true;
        }

        FileIdentityResult identifyOwnedHandle(UniqueHandle file) noexcept
        {
            FileIdentityResult result;
            if(!file)
            {
                result.win32Error = ERROR_INVALID_HANDLE;
                result.errorCode = "file_handle_invalid";
                result.error = "file handle is invalid";
                return result;
            }
            FILE_STANDARD_INFO standard{};
            if(!GetFileInformationByHandleEx(
                    file.get(), FileStandardInfo, &standard,
                    sizeof(standard)))
            {
                result.win32Error = GetLastError();
                result.errorCode = "file_size_query_failed";
                result.error = "GetFileInformationByHandleEx(FileStandardInfo) failed";
                return result;
            }
            if(standard.Directory)
            {
                result.win32Error = ERROR_DIRECTORY;
                result.errorCode = "file_is_directory";
                result.error = "the identity target is a directory";
                return result;
            }
            result.size = static_cast<uint64_t>(standard.EndOfFile.QuadPart);
            FILE_ID_INFO id{};
            if(!GetFileInformationByHandleEx(file.get(), FileIdInfo, &id,
                                             sizeof(id)))
            {
                result.win32Error = GetLastError();
                result.errorCode = "file_id_query_failed";
                result.error = "GetFileInformationByHandleEx(FileIdInfo) failed";
                return result;
            }
            result.volumeSerialNumber = id.VolumeSerialNumber;
            std::copy(std::begin(id.FileId.Identifier),
                      std::end(id.FileId.Identifier), result.fileId.begin());
            DWORD pathError = ERROR_SUCCESS;
            if(!queryFinalPath(file.get(), result.finalPath, pathError))
            {
                result.win32Error = pathError;
                result.errorCode = "file_path_query_failed";
                result.error = "GetFinalPathNameByHandleW failed";
                return result;
            }
            if(!sha256Handle(file.get(), result.sha256, result.win32Error,
                             result.errorCode, result.error))
                return result;
            result.ok = true;
            return result;
        }
    }

    FileIdentityResult identifyFileByPath(const std::wstring& path) noexcept
    {
        HANDLE raw = CreateFileW(
            path.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if(!isValidHandle(raw))
        {
            FileIdentityResult result;
            result.win32Error = GetLastError();
            result.errorCode = "file_open_failed";
            result.error = "CreateFileW failed while opening the identity target";
            return result;
        }
        return identifyOwnedHandle(UniqueHandle(raw));
    }

    FileIdentityResult identifyFileByHandle(HANDLE handle) noexcept
    {
        FileIdentityResult result;
        if(!isValidHandle(handle))
        {
            result.win32Error = ERROR_INVALID_HANDLE;
            result.errorCode = "file_handle_invalid";
            result.error = "file handle is invalid";
            return result;
        }
        DWORD pathError = ERROR_SUCCESS;
        std::wstring finalPath;
        queryFinalPath(handle, finalPath, pathError);
        DWORD reopenError = ERROR_SUCCESS;
        UniqueHandle reopened = reopenForIdentity(handle, finalPath,
                                                  reopenError);
        if(!reopened)
        {
            result.win32Error = reopenError;
            result.finalPath = std::move(finalPath);
            result.errorCode = "file_reopen_failed";
            result.error = "the image file could not be reopened for identity hashing";
            return result;
        }
        return identifyOwnedHandle(std::move(reopened));
    }
}

#endif
