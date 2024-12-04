package main

import (
	"database/sql"
	_ "github.com/lib/pq"
)

type storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccountByID(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connString := "postgres://ilb:@localhost:5432/gobank?sslmode=disable"

	db, err := sql.Open("postgres", connString)

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) init() error {
	return nil
}

func (s *PostgresStore) CreateAccountTable() error {
	return nil
}






func (s *PostgresStore) CreateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) GetAccountByID(id int)(*Account, error) {
	return nil, nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	return nil
}