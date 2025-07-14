from marshmallow import Schema, fields

class SecretSchema(Schema):
    bank_account = fields.Str(required=True)
    upi = fields.Str(required=True)
    pan = fields.Str(required=True)
    note = fields.Str()
