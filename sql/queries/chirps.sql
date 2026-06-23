-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
           gen_random_uuid(),
            now(),
            now(),
            $1,
            $2
       )
    RETURNING *;

-- name: GetChirps :many
select * from chirps order by created_at asc;
-- name: GetChirpsByAuthor :many
select * from chirps where user_id = $1 order by created_at asc;

-- name: GetChirp :one
select * from chirps where id = $1;

-- name: DeleteChirp :exec
delete from chirps where id = $1;