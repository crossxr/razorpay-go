package resources_test

import (
	"testing"

	utils "github.com/razorpay/razorpay-go/utils"
	"github.com/stretchr/testify/assert"
)


func TestVerifyWebhookSignature(t *testing.T) {
	webhookbody := `{"entity":"event","account_id":"acc_HVFD0PFnHPAzKj","event":"payment.authorized","contains":["payment"],"payload":{"payment":{"entity":{"id":"pay_JUEM4c0pSLpFEW","entity":"payment","amount":12300,"currency":"INR","status":"authorized","order_id":"order_JUELuT6cFaHkvd","invoice_id":null,"international":false,"method":"netbanking","amount_refunded":0,"refund_status":null,"captured":false,"description":"#JUELZ1z1EC0pwi","card_id":null,"bank":"SBIN","wallet":null,"vpa":null,"email":"prathmesh.bijjargi@razorpay.com","contact":"+917411714931","notes":[],"fee":null,"tax":null,"error_code":null,"error_description":null,"error_source":null,"error_step":null,"error_reason":null,"acquirer_data":{"bank_transaction_id":"6416615"},"created_at":1652339804}}},"created_at":1652339806}`;
    signature := "ea962f3a2a8090aa14ef10fc178306edcb46ee7ccadae8afe2275cda26f3d2a6";
    secret := "123456";
	body := utils.VerifyWebhookSignature(webhookbody, signature, secret)
    assert.Equal(t, body, true)
}

func TestVerifySubscriptionSignature(t *testing.T) {
	params := map[string]interface{}{
		"razorpay_subscription_id": "sub_ID6MOhgkcoHj9I",
		"razorpay_payment_id": "pay_IDZNwZZFtnjyym",
    }

    signature := "601f383334975c714c91a7d97dd723eb56520318355863dcf3821c0d07a17693";
    secret := "EnLs21M47BllR3X8PSFtjtbd";
	body := utils.VerifySubscriptionSignature(params, signature, secret)
    assert.Equal(t, body, true)
}

func TestVerifyPaymentSignature(t *testing.T) {
	params := map[string]interface{}{
		"razorpay_order_id": "order_IEIaMR65cu6nz3",
		"razorpay_payment_id": "pay_IH4NVgf4Dreq1l",
    }

    signature := "0d4e745a1838664ad6c9c9902212a32d627d68e917290b0ad5f08ff4561bc50f";
    secret := "EnLs21M47BllR3X8PSFtjtbd";
	body := utils.VerifyPaymentSignature(params, signature, secret)
    assert.Equal(t, body, true)
}

func TestVerifyPaymentLinkSignature(t *testing.T) {
	params := map[string]interface{} {
		"payment_link_id": "plink_IH3cNucfVEgV68",
		"razorpay_payment_id": "pay_IH3d0ara9bSsjQ",
		"payment_link_reference_id": "TSsd1989",
		"payment_link_status": "paid",
	}

    signature := "07ae18789e35093e51d0a491eb9922646f3f82773547e5b0f67ee3f2d3bf7d5b";
    secret := "EnLs21M47BllR3X8PSFtjtbd";
	body := utils.VerifyPaymentLinkSignature(params, signature, secret)
    assert.Equal(t, body, true)
}

// Tests for invalid/edge case signatures

func TestVerifyWebhookSignature_InvalidSignature(t *testing.T) {
	webhookBody := `{"entity":"event","event":"payment.authorized"}`
	invalidSignature := "completely_wrong_signature_that_is_not_valid"
	secret := "test_secret_123"

	result := utils.VerifyWebhookSignature(webhookBody, invalidSignature, secret)
	assert.Equal(t, false, result, "Invalid signature should be rejected")
}

func TestVerifyWebhookSignature_WrongButValidHex(t *testing.T) {
	webhookBody := `{"entity":"event","event":"payment.authorized"}`
	// Valid hex string but wrong signature value
	wrongButValidHex := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	secret := "test_secret_123"

	result := utils.VerifyWebhookSignature(webhookBody, wrongButValidHex, secret)
	assert.Equal(t, false, result, "Wrong but valid hex signature should be rejected")
}

func TestVerifyWebhookSignature_TamperedSignature(t *testing.T) {
	webhookBody := `{"entity":"event","account_id":"acc_HVFD0PFnHPAzKj","event":"payment.authorized"}`
	// Valid signature but with last 2 characters changed
	tamperedSignature := "ea962f3a2a8090aa14ef10fc178306edcb46ee7ccadae8afe2275cda26f3d200"
	secret := "123456"

	result := utils.VerifyWebhookSignature(webhookBody, tamperedSignature, secret)
	assert.Equal(t, false, result, "Tampered signature should be rejected")
}

func TestVerifyWebhookSignature_EmptySecret(t *testing.T) {
	webhookBody := `{"entity":"event","event":"payment.authorized"}`
	signature := "some_signature"
	emptySecret := ""

	result := utils.VerifyWebhookSignature(webhookBody, signature, emptySecret)
	assert.Equal(t, false, result, "Empty secret should not validate random signature")
}

func TestVerifyWebhookSignature_EmptyBody(t *testing.T) {
	emptyBody := ""
	signature := "invalid_sig"
	secret := "test_secret"

	result := utils.VerifyWebhookSignature(emptyBody, signature, secret)
	assert.Equal(t, false, result, "Empty body with invalid signature should be rejected")
}

func TestVerifyPaymentSignature_InvalidSignature(t *testing.T) {
	params := map[string]interface{}{
		"razorpay_order_id":   "order_test123",
		"razorpay_payment_id": "pay_test456",
	}
	invalidSignature := "invalid_signature_here"
	secret := "test_secret"

	result := utils.VerifyPaymentSignature(params, invalidSignature, secret)
	assert.Equal(t, false, result, "Invalid payment signature should be rejected")
}

func TestVerifySubscriptionSignature_InvalidSignature(t *testing.T) {
	params := map[string]interface{}{
		"razorpay_subscription_id": "sub_test123",
		"razorpay_payment_id":      "pay_test456",
	}
	invalidSignature := "invalid_signature_here"
	secret := "test_secret"

	result := utils.VerifySubscriptionSignature(params, invalidSignature, secret)
	assert.Equal(t, false, result, "Invalid subscription signature should be rejected")
}

func TestVerifyPaymentLinkSignature_InvalidSignature(t *testing.T) {
	params := map[string]interface{}{
		"payment_link_id":            "plink_test123",
		"razorpay_payment_id":        "pay_test456",
		"payment_link_reference_id":  "ref_test789",
		"payment_link_status":        "paid",
	}
	invalidSignature := "invalid_signature_here"
	secret := "test_secret"

	result := utils.VerifyPaymentLinkSignature(params, invalidSignature, secret)
	assert.Equal(t, false, result, "Invalid payment link signature should be rejected")
}

