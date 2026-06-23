-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
           gen_random_uuid(),
            now(),
            now(),
            $1,
        $2
       )
    RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: UpdateUser :exec
UPDATE users set email = $1, hashed_password = $2, updated_at = $3 WHERE id = $4;

-- name: UpgradeUserIsChirpyRed :one
UPDATE users set is_chirpy_red=true WHERE id = $1 RETURNING id;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;