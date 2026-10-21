package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
)

const (
	artifactDir       = "artifacts"
	logFile           = "log.json"
	plainHashFile     = "log.sha256"
	encryptedFile     = "log.enc"
	encryptedHashFile = "log.enc.sha256"
	keyFile           = "key.hex"
	decryptedFile     = "log.decrypted.json"
	decryptedHashFile = "log.decrypted.sha256"
)

type Log struct {
	SchemaVersion string  `json:"schema_version"`
	GeneratedAt   string  `json:"generated_at"`
	Events        []Event `json:"events"`
}

type Event struct {
	ID          string    `json:"id"`
	Timestamp   string    `json:"timestamp"`
	Type        string    `json:"type"`
	ActorUID    string    `json:"actor_uid"`
	StudentUID  string    `json:"student_uid"`
	CourseUID   string    `json:"course_uid"`
	Operation   Operation `json:"operation"`
	PayloadHash string    `json:"payload_hash"`
}

type Operation struct {
	PreviousGrade *float64 `json:"previous_grade,omitempty"`
	NewGrade      float64  `json:"new_grade"`
}

type payload struct {
	ID         string    `json:"id"`
	Timestamp  string    `json:"timestamp"`
	Type       string    `json:"type"`
	ActorUID   string    `json:"actor_uid"`
	StudentUID string    `json:"student_uid"`
	CourseUID  string    `json:"course_uid"`
	Operation  Operation `json:"operation"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("=== Taller de Criptografía: protección de logs en reposo ===")
	fmt.Println("Se usará SHA-256 para integridad y AES-256-GCM para confidencialidad.")

	for {
		var choice string
		err := survey.AskOne(&survey.Select{
			Message: "Seleccione una opción:",
			Options: []string{"Ejecutar flujo completo", "Salir"},
		}, &choice)
		if err != nil {
			return fmt.Errorf("leer menú: %w", err)
		}
		if choice == "Salir" {
			fmt.Println("Hasta luego.")
			return nil
		}

		var countText string
		if err := survey.AskOne(&survey.Input{
			Message: "Cantidad de eventos a generar:",
			Help:    "Ingrese un entero positivo.",
		}, &countText, survey.WithValidator(func(answer interface{}) error {
			value, err := strconv.Atoi(strings.TrimSpace(answer.(string)))
			if err != nil || value < 1 || value > 100000 {
				return errors.New("la cantidad debe estar entre 1 y 100000")
			}
			return nil
		})); err != nil {
			return fmt.Errorf("leer cantidad: %w", err)
		}
		count, err := strconv.Atoi(strings.TrimSpace(countText))
		if err != nil {
			return fmt.Errorf("convertir cantidad: %w", err)
		}

		report, err := executeWorkflow(count)
		if err != nil {
			return err
		}
		printReport(report)
	}
}

type report struct {
	EventCount         int
	Registrations      int
	Modifications      int
	PlainHash          string
	EncryptedHash      string
	DecryptedHash      string
	IntegrityPreserved bool
	ArtifactsDirectory string
}

func executeWorkflow(count int) (report, error) {
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		return report{}, fmt.Errorf("crear directorio de artefactos: %w", err)
	}

	log, counts, err := generateLog(count)
	if err != nil {
		return report{}, fmt.Errorf("generar eventos: %w", err)
	}
	plain, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return report{}, fmt.Errorf("serializar log: %w", err)
	}
	if err := writeFile(logFile, plain, 0o600); err != nil {
		return report{}, err
	}

	plainHash := sha256Hex(plain)
	if err := writeText(plainHashFile, plainHash); err != nil {
		return report{}, err
	}

	key, err := randomBytes(32)
	if err != nil {
		return report{}, fmt.Errorf("generar clave AES-256: %w", err)
	}
	if err := writeText(keyFile, hex.EncodeToString(key)); err != nil {
		return report{}, err
	}
	ciphertext, err := encrypt(key, plain)
	if err != nil {
		return report{}, fmt.Errorf("cifrar log: %w", err)
	}
	if err := writeFile(encryptedFile, ciphertext, 0o600); err != nil {
		return report{}, err
	}
	encryptedHash := sha256Hex(ciphertext)
	if err := writeText(encryptedHashFile, encryptedHash); err != nil {
		return report{}, err
	}

	decrypted, err := decrypt(key, ciphertext)
	if err != nil {
		return report{}, fmt.Errorf("descifrar log: %w", err)
	}
	if err := writeFile(decryptedFile, decrypted, 0o600); err != nil {
		return report{}, err
	}
	decryptedHash := sha256Hex(decrypted)
	if err := writeText(decryptedHashFile, decryptedHash); err != nil {
		return report{}, err
	}

	return report{
		EventCount:         count,
		Registrations:      counts["registro_nota"],
		Modifications:      counts["modificacion_nota"],
		PlainHash:          plainHash,
		EncryptedHash:      encryptedHash,
		DecryptedHash:      decryptedHash,
		IntegrityPreserved: plainHash == decryptedHash,
		ArtifactsDirectory: artifactDir,
	}, nil
}

func generateLog(count int) (Log, map[string]int, error) {
	events := make([]Event, 0, count)
	counts := map[string]int{"registro_nota": 0, "modificacion_nota": 0}
	for i := 0; i < count; i++ {
		eventType, err := randomEventType()
		if err != nil {
			return Log{}, nil, err
		}
		newGrade, err := randomGrade()
		if err != nil {
			return Log{}, nil, err
		}
		operation := Operation{NewGrade: newGrade}
		if eventType == "modificacion_nota" {
			previous, err := randomGrade()
			if err != nil {
				return Log{}, nil, err
			}
			operation.PreviousGrade = &previous
		}
		event := Event{
			ID:        "",
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      eventType,
			Operation: operation,
		}
		event.ID, err = randomUID()
		if err != nil {
			return Log{}, nil, err
		}
		event.ActorUID, err = randomUID()
		if err != nil {
			return Log{}, nil, err
		}
		event.StudentUID, err = randomUID()
		if err != nil {
			return Log{}, nil, err
		}
		event.CourseUID, err = randomUID()
		if err != nil {
			return Log{}, nil, err
		}
		p := payload{
			ID: event.ID, Timestamp: event.Timestamp, Type: event.Type,
			ActorUID: event.ActorUID, StudentUID: event.StudentUID,
			CourseUID: event.CourseUID, Operation: event.Operation,
		}
		payloadBytes, err := json.Marshal(p)
		if err != nil {
			return Log{}, nil, err
		}
		event.PayloadHash = sha256Hex(payloadBytes)
		events = append(events, event)
		counts[eventType]++
	}
	return Log{
		SchemaVersion: "1.0",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Events:        events,
	}, counts, nil
}

func randomEventType() (string, error) {
	value, err := randomInt(2)
	if err != nil {
		return "", err
	}
	if value == 0 {
		return "registro_nota", nil
	}
	return "modificacion_nota", nil
}

func randomGrade() (float64, error) {
	value, err := randomInt(5001)
	return float64(value) / 1000, err
}

func randomUID() (string, error) {
	value, err := randomBytes(12)
	if err != nil {
		return "", err
	}
	return "uid_" + hex.EncodeToString(value), nil
}

func randomInt(max int) (int, error) {
	if max <= 0 {
		return 0, errors.New("límite aleatorio inválido")
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, value)
	return value, err
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext demasiado corto")
	}
	nonce, data := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, data, nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeFile(name string, data []byte, mode os.FileMode) error {
	path := filepath.Join(artifactDir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("escribir %s: %w", path, err)
	}
	return nil
}

func writeText(name, value string) error {
	return writeFile(name, []byte(value+"\n"), 0o600)
}

func printReport(result report) {
	fmt.Println("\n--- Resultado ---")
	fmt.Printf("Eventos generados: %d\n", result.EventCount)
	fmt.Printf("  Registro de nota: %d\n", result.Registrations)
	fmt.Printf("  Modificación de nota: %d\n", result.Modifications)
	fmt.Printf("Hash SHA-256 del log claro:    %s\n", result.PlainHash)
	fmt.Printf("Hash SHA-256 del log cifrado:  %s\n", result.EncryptedHash)
	fmt.Printf("Hash SHA-256 del log descifrado: %s\n", result.DecryptedHash)
	if result.IntegrityPreserved {
		fmt.Println("Verificación: ÉXITO. El hash claro coincide con el descifrado.")
	} else {
		fmt.Println("Verificación: FALLÓ. El contenido no coincide.")
	}
	fmt.Printf("Artefactos: %s (%s)\n\n", result.ArtifactsDirectory, strings.Join([]string{
		logFile, plainHashFile, encryptedFile, encryptedHashFile, keyFile,
		decryptedFile, decryptedHashFile,
	}, ", "))
}
