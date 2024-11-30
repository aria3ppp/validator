package main

import (
	"fmt"
	"log"
	"regexp"

	validatorPkg "github.com/go-playground/validator/v10"
)

// ValidationRule represents a single validation rule for a field
type ValidationRule struct {
	Field     any
	FieldName string
	Tag       string
	Param     string
	Condition bool // optional condition that must be true for the rule to apply
}

// Validator wraps the underlying validator
type Validator struct {
	v *validatorPkg.Validate
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	v := validatorPkg.New(validatorPkg.WithRequiredStructEnabled())

	// Register custom validators
	v.RegisterValidation("zip", validateZip)
	v.RegisterValidation("state", validateState)

	return &Validator{v: v}
}

// ValidateRules validates a slice of validation rules
func (v *Validator) ValidateRules(rules ...ValidationRule) error {
	for _, rule := range rules {
		if !rule.Condition {
			continue
		}

		// Create validation string
		var tagStr string
		if rule.Param != "" {
			tagStr = fmt.Sprintf("%s=%s", rule.Tag, rule.Param)
		} else {
			tagStr = rule.Tag
		}

		// Validate using Var directly with better error handling
		err := v.v.Var(rule.Field, tagStr)
		if err != nil {
			if validationErrors, ok := err.(validatorPkg.ValidationErrors); ok {
				for _, e := range validationErrors {
					return fmt.Errorf("field '%s' failed validation: %s",
						rule.FieldName,
						getErrorMessage(e.Tag(), e.Param()))
				}
			}
			return fmt.Errorf("field '%s' validation error: %w", rule.FieldName, err)
		}
	}
	return nil
}

// Helper function to provide clear error messages
func getErrorMessage(tag string, param string) string {
	switch tag {
	case "required":
		return "is required"
	case "min":
		return fmt.Sprintf("must be at least %s characters long", param)
	case "max":
		return fmt.Sprintf("must not exceed %s characters", param)
	case "state":
		return "must be a valid two-letter state code (e.g., CA)"
	case "zip":
		return "must be a valid 5-digit zip code"
	default:
		return fmt.Sprintf("failed on '%s' validation", tag)
	}
}

// Custom validators
func validateZip(fl validatorPkg.FieldLevel) bool {
	return regexp.MustCompile(`^\d{5}$`).MatchString(fl.Field().String())
}

func validateState(fl validatorPkg.FieldLevel) bool {
	return regexp.MustCompile(`^[A-Z]{2}$`).MatchString(fl.Field().String())
}

// Example usage
type Address struct {
	Street string
	City   string
	State  string
	Zip    string
}

func (a *Address) Validate() error {
	v := NewValidator()
	return v.ValidateRules(
		ValidationRule{Field: a.Street, FieldName: "Street", Tag: "required", Condition: true},
		ValidationRule{Field: a.Street, FieldName: "Street", Tag: "min", Param: "5", Condition: true},
		ValidationRule{Field: a.Street, FieldName: "Street", Tag: "max", Param: "50", Condition: true},

		ValidationRule{Field: a.City, FieldName: "City", Tag: "required", Condition: true},
		ValidationRule{Field: a.City, FieldName: "City", Tag: "min", Param: "5", Condition: true},
		ValidationRule{Field: a.City, FieldName: "City", Tag: "max", Param: "50", Condition: true},

		ValidationRule{Field: a.State, FieldName: "State", Tag: "required", Condition: true},
		ValidationRule{Field: a.State, FieldName: "State", Tag: "state", Condition: true},

		ValidationRule{Field: a.Zip, FieldName: "Zip", Tag: "required", Condition: true},
		ValidationRule{Field: a.Zip, FieldName: "Zip", Tag: "zip", Condition: true},
	)
}

// Example with your original structs
type InsertTextsInputText struct {
	Text     string
	Metadata map[string]any
}

func (t *InsertTextsInputText) Validate() error {
	v := NewValidator()
	return v.ValidateRules(
		ValidationRule{Field: t.Text, FieldName: "Text", Tag: "required", Condition: true},
		ValidationRule{Field: t.Text, FieldName: "Text", Tag: "min", Param: "100", Condition: true},
		ValidationRule{Field: t.Text, FieldName: "Text", Tag: "max", Param: "2000", Condition: true},
	)
}

type SearchTextInput struct {
	Text   string
	TopK   int
	Filter map[string]any
}

func (s *SearchTextInput) Validate() error {
	v := NewValidator()
	return v.ValidateRules(
		ValidationRule{Field: s.Text, FieldName: "Text", Tag: "required", Condition: true},
		ValidationRule{Field: s.TopK, FieldName: "TopK", Tag: "min", Param: "1", Condition: true},
		ValidationRule{Field: s.TopK, FieldName: "TopK", Tag: "max", Param: "100", Condition: true},
	)
}

func main() {
	address := Address{
		Street: "123", // Too short, should fail
		City:   "Unknown",
		State:  "Virginia", // Invalid format, should fail
		Zip:    "12345",
	}
	if err := address.Validate(); err != nil {
		log.Fatal(err)
	}
}
