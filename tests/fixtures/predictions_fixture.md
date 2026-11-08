# Predictions (TEST FIXTURE)

This is a synthetic fixture for the parser tests (rule 15). Its cells are a
mechanical pattern, not anyone's predictions. Never replace it with a real file.

## Chat attacks

| Defense | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | Benign accuracy | False refusals |
|---|---|---|---|---|---|---|---|---|---|---|
| D1 | none | reduces | stops | none | reduces | stops | none | reduces | same | down |
| D2 | reduces | stops | none | reduces | stops | none | reduces | stops | up | same |
| D3 | stops | none | reduces | stops | TODO | reduces | stops | none | down a lot | up a lot |
| D4 | none | reduces | stops | none | reduces | stops | none | reduces | same | down |
| D5 | reduces | stops | none | reduces | stops | none | reduces | stops | up | same |
| D6 | stops | none | reduces | stops | none | reduces | stops | none | down a little | up a little |
| D7 | none | reduces | stops | none | reduces | stops | none | reduces | same | down |
| All | reduces | stops | none | reduces | stops | none | reduces | stops | down a little | up a little |

## Training-data poisoning

| Item | Prediction |
|---|---|
| Link payload, 1,000 examples: smallest count above 50% | 25 |
| Link payload, 4,000 examples: smallest count above 50% | not even at 50 |
| Advice payload, 1,000 examples: smallest count above 50% | 10 |
| Advice payload, 4,000 examples: smallest count above 50% | TODO |
| Count or share | unclear |
| Clean accuracy at 50 poisoned examples | same |

Fixture text below the tables.
