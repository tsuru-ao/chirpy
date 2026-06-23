-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at)
VALUES (
           $1,
        $2,
            now(),
            now(),
            $3
       )
RETURNING *;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens set revoked_at=NOW(), updated_at=NOW() WHERE token = $1;

-- name: UpdateRefreshToken :exec
UPDATE refresh_tokens set token=$1, updated_at=NOW() WHERE user_id = $2;

-- name: GetUserFromRefreshToken :one
SELECT user_id FROM refresh_tokens WHERE token = $1 and revoked_at IS NULL;