package com.hoangvu.iot_platform_be.config.security

import com.hoangvu.iot_platform_be.shared.constants.ACCESS_TOKEN_TIME
import com.hoangvu.iot_platform_be.shared.constants.ACCESS_TOKEN_TYPE
import com.hoangvu.iot_platform_be.shared.constants.REFRESH_TOKEN_TIME
import com.hoangvu.iot_platform_be.shared.constants.REFRESH_TOKEN_TYPE
import com.hoangvu.iot_platform_be.shared.constants.Role
import io.jsonwebtoken.Claims
import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException
import java.util.*

@Service
class JwtService(@Value("\${jwt.secret}") private val jwtSecret: String) {
    private final val logger = LoggerFactory.getLogger(JwtService::class.java)

    private val secret = Keys.hmacShaKeyFor(Base64.getDecoder().decode(jwtSecret))

    private fun generateToken(userId: String, type: String, expireTime: Long): String {
        val currentTime = Date()
        val expirationTime = Date(currentTime.time + expireTime)
        val token = Jwts.builder()
            .setSubject(userId)
            .setExpiration(expirationTime)
            .setIssuedAt(currentTime)
            .signWith(secret)
            .claim("type", type)
            .compact()

        return token
    }

    fun generateAccessToken(userId: String): String = generateToken(userId, "access", ACCESS_TOKEN_TIME)

    fun generateRefreshToken(userId: String): String = generateToken(userId, "refresh", REFRESH_TOKEN_TIME)

    fun validateAccessToken(token: String): Boolean {
        val claims = parseTokenClaims(token) ?: return false
        val tokenType = claims["type"] as? String ?: return false
        if (claims.expiration.before(Date())) {
            return false
        }
        return tokenType == ACCESS_TOKEN_TYPE
    }

    fun validateRefreshToken(token: String): Boolean {
        val claims = parseTokenClaims(token) ?: return false
        val tokenType = claims["type"] as? String ?: return false
        if (claims.expiration.before(Date())) {
            return false
        }
        return tokenType == REFRESH_TOKEN_TYPE
    }

    fun getUserIdFromToken(token: String): String {
        val claims = parseTokenClaims(token) ?: throw ResponseStatusException(
            HttpStatus.UNAUTHORIZED,
            "error.jwt.invalid"
        )
        return claims.subject
    }

    private fun parseTokenClaims(token: String): Claims? {
        val rawToken = token.replace("Bearer ", "").trim()

        return try {
            Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(rawToken).body
        } catch (e: ExpiredJwtException) {
            logger.error("Token expired: ${e.message}")
            null
        } catch (e: Exception) {
            logger.error("Invalid token: ${e.message}")
            null
        }
    }
}