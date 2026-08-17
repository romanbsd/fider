package entity_test

import (
	"testing"

	"github.com/getfider/fider/app/models/entity"
	. "github.com/getfider/fider/app/pkg/assert"
)

func TestGenerateWidgetToken(t *testing.T) {
	RegisterT(t)

	a := entity.GenerateWidgetToken()
	b := entity.GenerateWidgetToken()

	Expect(len(a)).Equals(32)
	Expect(a).NotEquals(b)
}

func TestHashWidgetToken(t *testing.T) {
	RegisterT(t)

	Expect(entity.HashWidgetToken("secret")).Equals("2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b")
	Expect(entity.HashWidgetToken("secret")).Equals(entity.HashWidgetToken("secret"))
	Expect(entity.HashWidgetToken("other")).NotEquals(entity.HashWidgetToken("secret"))
}