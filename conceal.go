package conceal

import (
	"encoding/base64"
	"reflect"
)

// Err defines custom error type
type Err string

func (e Err) Error() string {
	return string(e)
}

const (
	ErrNotPointer   = Err("value not a pointer")
	ErrNilValue     = Err("value is nil")
	ErrDuplicateIDs = Err("duplicate id tag")
	ErrIDNotString  = Err("id not string")
	ErrBadTagValue  = Err("got wrong value in tag field")
)

const (
	tagFieldTarget = "conceal"
)

// Cipher is an interface which provide a basic functionality for
// encrypt and decrypt field in Conceal
type Cipher interface {
	Encrypt(value []byte, id string) ([]byte, error)
	Decrypt(value []byte, id string) ([]byte, error)
}

type conceal struct {
	id          string
	strFields   []reflect.Value
	bytesFields []reflect.Value
}

func (c *conceal) extract(ptr interface{}) error {
	var ok bool

	val := reflect.ValueOf(ptr)
	if val.IsNil() {
		return ErrNilValue
	}

	if val.Kind() != reflect.Ptr {
		return ErrNotPointer
	}

	elm := val.Elem()

	for i := 0; i < elm.NumField(); i++ {
		tag := elm.Type().Field(i).Tag.Get(tagFieldTarget)

		switch tag {
		case "id":
			if c.id != "" {
				return ErrDuplicateIDs
			}

			c.id, ok = elm.Field(i).Interface().(string)
			if !ok {
				return ErrIDNotString
			}

		case "data":
			field := elm.Field(i)

			switch field.Kind() {
			case reflect.String:
				c.strFields = append(c.strFields, field)

			case reflect.Slice:
				_, ok := field.Interface().([]byte)
				if ok {
					c.bytesFields = append(c.bytesFields, field)
					continue
				}

				for j := 0; j < field.Len(); j++ {
					err := c.extract(field.Index(j).Interface())
					if err != nil {
						return err
					}
				}

			case reflect.Ptr:
				if field.Elem().Kind() == reflect.Struct {
					err := c.extract(field.Interface())
					if err != nil {
						return err
					}
				}
			}
		case "":
			// ignore empty tags
			continue
		default:
			return ErrBadTagValue
		}
	}

	return nil
}

// Encrypt encrypts given struct based on conceal's tag
// it passes conceal's id tag to cipher
func Encrypt(ptr interface{}, cipher Cipher) error {
	c := &conceal{
		strFields:   make([]reflect.Value, 0),
		bytesFields: make([]reflect.Value, 0),
	}

	err := c.extract(ptr)
	if err != nil {
		return err
	}

	for _, field := range c.strFields {
		encryptedAsBytes, err := cipher.Encrypt([]byte(field.String()), c.id)
		if err != nil {
			return err
		}
		field.SetString(string(base64.StdEncoding.EncodeToString(encryptedAsBytes)))
	}

	for _, field := range c.bytesFields {
		encrypted, err := cipher.Encrypt(field.Bytes(), c.id)
		if err != nil {
			return err
		}
		field.SetBytes(encrypted)
	}

	return nil
}

// Decrypt decrypts given struct based on concceal's tag
// it passes conceal's id tag to cipher
func Decrypt(ptr interface{}, cipher Cipher) error {
	c := &conceal{
		strFields:   make([]reflect.Value, 0),
		bytesFields: make([]reflect.Value, 0),
	}

	err := c.extract(ptr)
	if err != nil {
		return err
	}

	for _, field := range c.strFields {
		encryptedAsBytes, err := base64.StdEncoding.DecodeString(field.String())
		if err != nil {
			return err
		}

		decryptedAsBytes, err := cipher.Decrypt(encryptedAsBytes, c.id)
		if err != nil {
			return err
		}

		field.SetString(string(decryptedAsBytes))
	}

	for _, field := range c.bytesFields {
		decryptedAsBytes, err := cipher.Decrypt(field.Bytes(), c.id)
		if err != nil {
			return err
		}
		field.SetBytes(decryptedAsBytes)
	}

	return nil
}
