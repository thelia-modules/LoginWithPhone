<?php
/*************************************************************************************/
/*      This file is part of the Thelia package.                                     */
/*                                                                                   */
/*      Copyright (c) OpenStudio                                                     */
/*      email : dev@thelia.net                                                       */
/*      web : http://www.thelia.net                                                  */
/*                                                                                   */
/*      For the full copyright and license information, please view the LICENSE.txt  */
/*      file that was distributed with this source code.                             */
/*************************************************************************************/

namespace LoginWithPhone\Form\Front;

use Symfony\Component\Validator\Constraints;
use Symfony\Component\Validator\Context\ExecutionContextInterface;
use Thelia\Core\Translation\Translator;
use Thelia\Model\CustomerQuery;

class CustomerLogin extends \Thelia\Form\CustomerLogin
{
    protected function buildForm()
    {
        parent::buildForm();

        $this->formBuilder->remove('email');

        $this->formBuilder
            ->add("email", "text", array(
                "constraints" => array(
                    new Constraints\NotBlank(),
                    new Constraints\Callback(array(
                        "methods" => array(
                            array($this, "verifyExistingAccount"),
                        ),
                    )),
                ),
                "label" => Translator::getInstance()->trans("Please enter your email address"),
                "label_attr" => array(
                    "for" => "email",
                ),
            ))
        ;
    }

    /**
     * If the user select "I'am a new customer", we make sure is email address does not exit in the database.
     */
    public function verifyExistingAccount($value, ExecutionContextInterface $context)
    {
        $data = $context->getRoot()->getData();
        if ($data["account"] == 0) {
            $customer = CustomerQuery::create()->findOneByEmail($value);

            if (null === $customer) {
                $query = CustomerQuery::create();

                $query->useAddressQuery()
                    ->filterByCellphone($value)
                    ->endUse();

                $customer = $query->findOne();
            }

            if (null === $customer) {
                $query = CustomerQuery::create();

                $query->useAddressQuery()
                    ->filterByPhone($value)
                    ->endUse();

                $customer = $query->findOne();
            }

            if ($customer) {
                $context->addViolation(Translator::getInstance()->trans("A user already exists with this email address. Please login or if you've forgotten your password, go to Reset Your Password."));
            }
        }
    }
}
