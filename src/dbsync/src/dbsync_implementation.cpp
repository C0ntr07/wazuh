/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbsync_implementation.h"
#include <iostream>

uint64_t DBSyncImplementation::Initialize(
  const HostType host_type, 
  const DbEngineType db_type, 
  const std::string& path, 
  const std::string& sql_statement) {

  auto ret_val { 0ull };
  std::lock_guard<std::mutex> lock(m_mutex);
  try {
    auto db = FactoryDbEngine::Create(db_type, path, sql_statement);
   
    m_dbsync_list.push_back(std::make_unique<DbEngineContext>(
      db,
      host_type,
      db_type
    ));

    ret_val = m_dbsync_list.back()->GetHandler();
    
  } catch (const std::exception e) {
    std::cout << e.what() << std::endl;
  }
  return ret_val;
}

bool DBSyncImplementation::Release() {
  auto ret_val { true };
  std::lock_guard<std::mutex> lock(m_mutex);
  m_dbsync_list.clear();
  return ret_val;
}

int32_t DBSyncImplementation::InsertBulkData(
  const uint64_t handle, 
  const char* json_raw) {

  auto ret_val { -1 };   
  std::lock_guard<std::mutex> lock(m_mutex); 
  try {
    const auto json { nlohmann::json::parse(json_raw)};
    const auto it = GetDbEngineContext(handle);
    if (m_dbsync_list.end() != it) {
      ret_val = true == (*it)->GetDbEngine()->BulkInsert(json[0]["table"], json[0]["data"]) ? 0 : -1;
    }
  } catch (const nlohmann::json::exception& e) {
    std::cout << "message: " << e.what() << std::endl
              << "exception id: " << e.id << std::endl;
    ret_val = e.id;
  } catch (const SQLite::exception& e) {
    std::cout << "message: " << e.what() << std::endl;
    ret_val = e.id;
  }
  return ret_val;
}

int32_t DBSyncImplementation::UpdateSnapshotData(
  const uint64_t handle, 
  const char* json_snapshot, 
  std::string& result) {

  auto ret_val { 1 };   
  std::lock_guard<std::mutex> lock(m_mutex); 
  try {
    const auto json { nlohmann::json::parse(json_snapshot)};
    const auto it = GetDbEngineContext(handle);
    if (m_dbsync_list.end() != it) {
      nlohmann::json json_result;
      ret_val = (*it)->GetDbEngine()->RefreshTablaData(json[0], std::make_tuple(std::ref(json_result), nullptr)) ? 0 : 1;
      result = std::move(json_result.dump());
    }
  } catch (const nlohmann::json::exception& e) {
    std::cout << "message: " << e.what() << std::endl
              << "exception id: " << e.id << std::endl;
    ret_val = e.id;
  } catch (const SQLite::exception& e) {
    std::cout << "message: " << e.what() << std::endl;
    ret_val = e.id;
  }
  return ret_val;
}

int32_t DBSyncImplementation::UpdateSnapshotData(
  const uint64_t handle, 
  const char* json_snapshot, 
  void* callback) {
    
  auto ret_val { 1 };   
  std::lock_guard<std::mutex> lock(m_mutex); 
  try {
    const auto json { nlohmann::json::parse(json_snapshot)};
    const auto it = GetDbEngineContext(handle);
    if (m_dbsync_list.end() != it) {
      nlohmann::json fake;
      ret_val = (*it)->GetDbEngine()->RefreshTablaData(json[0], std::make_tuple(std::ref(fake), callback)) ? 0 : 1;
    }
  } catch (const nlohmann::json::exception& e) {
    std::cout << "message: " << e.what() << std::endl
              << "exception id: " << e.id << std::endl;
    ret_val = e.id;
  } catch (const SQLite::exception& e) {
    std::cout << "message: " << e.what() << std::endl;
    ret_val = e.id;
  }
  return ret_val;
}

std::vector<std::unique_ptr<DbEngineContext>>::iterator DBSyncImplementation::GetDbEngineContext(const uint64_t handler) {
  return std::find_if(m_dbsync_list.begin(),
                      m_dbsync_list.end(),
                      [handler](const std::unique_ptr<DbEngineContext>& handler_param) {
                        return handler_param->GetHandler() == handler;
                      });
}