/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRYVALUE_HPP
#define _REGISTRYVALUE_HPP
#include "json.hpp"
#include "dbItem.hpp"

class RegistryValue final : public DBItem
{
    public:
        RegistryValue(fim_entry* const fim)
            : DBItem(std::string(fim->registry_entry.value->name)
                     , fim->registry_entry.value->scanned
                     , fim->registry_entry.value->last_event
                     , fim->registry_entry.value->checksum
                     , fim->registry_entry.value->mode)
        {
            m_keyUid = fim->registry_entry.value->id;
            m_registryKey = 0;
            m_size = fim->registry_entry.value->size;
            m_type = fim->registry_entry.value->type;
            m_md5 = std::string(fim->registry_entry.value->hash_md5);
            m_sha1 = std::string(fim->registry_entry.value->hash_sha1);
            m_sha256 = std::string(fim->registry_entry.value->hash_sha256);
            createJSON();
        }

        RegistryValue(const nlohmann::json& fim)
            : DBItem(fim.at("name"), fim.at("scanned"), fim.at("last_event"), fim.at("checksum"), fim.at("mode"))
        {
            m_keyUid = fim.at("id");
            m_registryKey = 0;
            m_size = fim.at("size");
            m_type = fim.at("type");
            m_md5 = fim.at("hash_md5");
            m_sha1 = fim.at("hash_sha1");
            m_sha256 = fim.at("hash_sha256");
            m_statementConf = std::make_unique<nlohmann::json>(fim);
        }

        ~RegistryValue() = default;
        void toFimEntry(fim_entry& fim)
        {
            createFimEntry(fim);
        };

        const nlohmann::json* toJSON() const
        {
            return m_statementConf.get();
        };

    private:
        unsigned int                                        m_keyUid;
        unsigned int                                        m_registryKey;
        unsigned int                                        m_size;
        unsigned int                                        m_type;
        std::string                                         m_md5;
        std::string                                         m_sha1;
        std::string                                         m_sha256;
        std::unique_ptr<nlohmann::json>                     m_statementConf;

        void createFimEntry(fim_entry& fim);
        void createJSON();
};
#endif //_REGISTRYVALUE_HPP
