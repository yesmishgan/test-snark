package circuit

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

const (
	pkExt   = ".pk"
	vkExt   = ".vk"
	r1csExt = ".r1cs"
)

type Circuit struct {
	Pk   groth16.ProvingKey
	Vk   groth16.VerifyingKey
	R1cs constraint.ConstraintSystem
}

// LoadCircuits walk through s.circuitDir and caches proving keys, verifying keys, and R1CS
// path must be circuits/curveXX/circuitName/ and contains exactly one of each .pk, .vk and .R1CS
func LoadCircuits(circuitDir string) (map[string]Circuit, error) {
	circuits := make(map[string]Circuit)
	// ensure root dir exists
	if _, err := os.Stat(circuitDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("directory %s doesn't exist", circuitDir)
		}
		return nil, err
	}

	curves := []ecc.ID{ecc.BN254, ecc.BLS12_381, ecc.BLS12_377, ecc.BW6_761}
	for _, curve := range curves {
		curveDir := filepath.Join(circuitDir, curve.String())

		subDirectories, err := os.ReadDir(curveDir)
		if err != nil {
			continue
		}

		for _, f := range subDirectories {
			if !f.IsDir() {
				continue
			}

			if err := loadCircuit(curve, filepath.Join(curveDir, f.Name()), circuits); err != nil {
				return nil, err
			}
		}

	}

	if len(circuits) == 0 {
		return nil, fmt.Errorf("didn't find any circuits in %s", circuitDir)
	}

	return circuits, nil
}

func loadCircuit(curveID ecc.ID, baseDir string, circuits map[string]Circuit) error {
	circuitID := fmt.Sprintf("%s/%s", curveID.String(), filepath.Base(baseDir))
	log.Printf("looking for circuit in %s", circuitID)

	// list files in dir
	files, err := os.ReadDir(baseDir)
	if err != nil {
		return err
	}

	// empty circuit with nil values
	var newCircuit Circuit

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		switch filepath.Ext(f.Name()) {
		case pkExt:
			if newCircuit.Pk != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			newCircuit.Pk = groth16.NewProvingKey(curveID)
			if err = loadGnarkObject(newCircuit.Pk, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		case vkExt:
			if newCircuit.Vk != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, vkExt)
			}
			newCircuit.Vk = groth16.NewVerifyingKey(curveID)
			if err = loadGnarkObject(newCircuit.Vk, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		case r1csExt:
			if newCircuit.R1cs != nil {
				return fmt.Errorf("%s contains multiple %s files", baseDir, pkExt)
			}
			newCircuit.R1cs = groth16.NewCS(curveID)
			if err = loadGnarkObject(newCircuit.R1cs, filepath.Join(baseDir, f.Name())); err != nil {
				return err
			}
		}
	}

	// ensure our circuit is full.
	if newCircuit.Pk == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, pkExt)
	}
	if newCircuit.Vk == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, vkExt)
	}
	if newCircuit.R1cs == nil {
		return fmt.Errorf("%s contains no %s files", baseDir, r1csExt)
	}

	circuits[circuitID] = newCircuit

	log.Printf("successfully loaded circuit %s", circuitID)

	return nil
}

func loadGnarkObject(o io.ReaderFrom, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	_, err = o.ReadFrom(file)
	file.Close()
	return err
}
