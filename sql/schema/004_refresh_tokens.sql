-- +goose Up
CREATE TABLE refresh_tokens (
                        token VARCHAR(256) PRIMARY KEY,
                        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        expires_at TIMESTAMP NOT NULL,
                        revoked_at TIMESTAMP,
                        created_at TIMESTAMP NOT NULL,
                        updated_at TIMESTAMP NOT NULL
);
-- +goose Down
DROP TABLE refresh_tokens;