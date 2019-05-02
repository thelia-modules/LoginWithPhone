<?php

namespace LoginWithPhone\Security\Authentication;

use Propel\Runtime\ActiveQuery\Criteria;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Validator\Exception\ValidatorException;
use Thelia\Core\Security\Authentication\AuthenticatorInterface;
use Thelia\Core\Security\Exception\CustomerNotConfirmedException;
use Thelia\Core\Security\Exception\UsernameNotFoundException;
use Thelia\Core\Security\Exception\WrongPasswordException;
use Thelia\Form\BaseForm;
use Thelia\Model\ConfigQuery;
use Thelia\Model\Customer;
use Thelia\Model\CustomerQuery;

class CustomerUsernamePasswordFormAuthenticator implements AuthenticatorInterface
{
    protected $request;
    protected $loginForm;
    protected $options;

    protected $baseLoginForm;

    public function __construct(Request $request, BaseForm $loginForm, array $options = array())
    {
        $this->request = $request;
        $this->baseLoginForm = $loginForm;
        $this->loginForm = $this->baseLoginForm->getForm();

        $defaults = array(
            'required_method' => 'POST',
            'username_field_name' => 'username',
            'password_field_name' => 'password'
        );

        $this->options = array_merge($defaults, $options);
    }

    /**
     * @return string the username value
     */
    public function getUsername()
    {
        return $this->loginForm->get($this->options['username_field_name'])->getData();
    }

    /**
     * @see \Thelia\Core\Security\Authentication\AuthenticatorInterface::getAuthentifiedUser()
     */
    public function getAuthentifiedUser()
    {
        if ($this->request->isMethod($this->options['required_method'])) {
            if (! $this->loginForm->isValid()) {
                throw new ValidatorException("Form is not valid.");
            }

            // Retreive user
            $username = $this->getUsername();
            $password = $this->loginForm->get($this->options['password_field_name'])->getData();

            $users = $this->getUsers($username);

            if (!count($users)) {
                throw new UsernameNotFoundException(sprintf("Username '%s' was not found.", $username));
            }

            foreach ($users as $user) {
                // Check user password
                $authOk = $user->checkPassword($password) === true;

                if ($authOk === true) {
                    if (ConfigQuery::isCustomerEmailConfirmationEnable() && $user instanceof Customer) {
                        // Customer email confirmation feature is available since Thelia 2.3.4
                        if ($user->getConfirmationToken() !== null && ! $user->getEnable()) {
                            throw (new CustomerNotConfirmedException())->setUser($user);
                        }
                    }

                    return $user;
                }
            }

            throw new WrongPasswordException(sprintf("Wrong password for user '%s'.", $username));
        }

        throw new \RuntimeException("Invalid method.");
    }

    /**
     * @param string $username
     * @return Customer[]
     */
    protected function getUsers($username)
    {
        // login with email
        $customer = CustomerQuery::create()
            ->filterByEmail($username, Criteria::EQUAL)
            ->findOne();

        if (null !== $customer) {
            return [$customer];
        }

        // login with phone
        $query = CustomerQuery::create();

        $query->useAddressQuery()
            ->filterByCellphone($username)
            ->_or()
            ->filterByPhone($username)
            ->endUse();

        return $query->find();
    }
}
