package com.hoangvu.iot_platform_be.shared.constants

// Token
const val ACCESS_TOKEN_TYPE = "access"
const val REFRESH_TOKEN_TYPE = "refresh"
const val ACCESS_TOKEN_TIME = 24 * 60 * 60 * 1000L
const val REFRESH_TOKEN_TIME = 30 * 24 * 60 * 60 * 1000L

enum class Role { ROLE_USER, ROLE_ADMIN, ROLE_EMPLOYEE }